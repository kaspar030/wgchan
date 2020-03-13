#ifndef WGCHAN_H
#define WGCHAN_H

/* struct holding identity / key information */
typedef struct {
    uint8_t priv_key[WGCHAN_PRIVKEY_LEN];
    uint8_t pub_key[WGCHAN_PRIVKEY_LEN];
} wgchan_id_t;

/* create keys */
wgchan_create_id(wgchan_id_t *id);

/* forward declaration of operations struct */
typedef struct wgchan_ops wgchan_ops_t;

/* struct holding channel state */
typedef struct {
    // ...
    const wgchan_ops_t *ops; /* defined below */
    void *context; /**< opaque pointer to some user supplied context data */
} wgchan_t;

/* this struct holds transport / system specific functions */
struct wgchan_ops {
    /* initlialization hook.
     * this might set up e.g., asynchronous callbacks of an underlying UDP socket, ...
     */
    int (*init)(wgchan_t *wgchan);

    /* a wgchan instance needs to know how to send encrypted data.
     * This defines a corresponding function signature. */
    ssize_t (*send)(wgchan_t *wgchan, uint8_t *buf, size_t buf_len);

    /* a wgchan instance needs a way to pass on decrypted channel messages.
     * This defines a corresponding function signature. */
    ssize_t (*handle_decrypted)(wgchan_t *wgchan, uint8_t *buf, size_t buf_len);

    /* wireguard protocol needs a way to get the current time in ms */
    uint32_t (*get_time_ms)(void);

    /* this provides wgchan with a function to trigger a timeout.
     * Maybe limit this to one timeout per wgchan. */
    void (*set_timeout)(wgchan_t *wgchan, uint32_t timeout_in_ms);

    /* this callback checks the peer's identity.
     * Will be called after handshaking. */
    bool (*check_peer_id)(wgchan_t *wgchan, uint8_t *peer_pk, size_t peer_pk_len);
};


/* something to initialize the state.
 * expects preallocated `wgchan`.*/
wgchan_init(wgchan_t *wgchan, wgchan_id_t *id,
            wgchan_ops_t *ops, void *context);

/* called by system if a timeout set using wgchan->ops->set_simeout() has expired */
void wgchan_trigger_timeout(wgchan_t *wgchan);

/* set up channel (initiator side).
 * will maybe use wg_chan->send_fn to send initiation packet ...
 * expects `wgchan` to be initialized. */
wgchan_connect(wgchan_t *wgchan);

/* set up channel ("server" side).
 * expects `wgchan` to be initialized.
 */
wgchan_accept(wgchan_t *wgchan);

/* something to asynchronously feed incoming encrypted messages to the channel */
wgchan_handle_incoming(wgchan_t *wgchan, uint8_t *buf, size_t buf_len);

/** application level API **/
/* something to send messages to the channel */
wgchan_send(wgchan_t *wgchan, uint8_t *buf, size_t buf_len);
/* receiving messages will be triggered by asynchronously calling wgchan->ops->handle_decrypted() */


/***********************/
/* example on receiver side */
/* 
 * This has a pseudocode (missing implementation) harness around using sock_udp
 * (RIOT's udp api).
 */

/* locally defined struct holding context data */
typedef struct {
    sock_udp_ep_t remote;
    wgchan_t wgchan;
} wgchan_sock_udp_t;

wgchan_sock_udp_t udp_channels[MAX_CHANNELS];

wgchan_t *wgchan_find_udp_channel(wgchan_sock_udp_t *channels, sock_udp_ep_t *remote) {
    for (size_t i = 0; i < MAX_CHANNELS; i++) {
        if (sock_udp_ep_equal(remote, &channels[i].remote)) {
            return &&channels[i].remote;
        }
    }
}

wgchan_t *wgchan_find_unused(wgchan_sock_udp_t *channels)
{
    // ...
}

wgchan_rx_loop(sock_udp_ep_t *local)
{
    sock_udp_t sock;
    sock_udp_ep_t remote;

    sock_udp_create(&sock, local, NULL, 0);

    while (1) {
        /* receive UDP packet */
        sock_udp_recv(&sock, buf, bufsize, -1, &remote);
        /* find existing channel */
        wgchan_t *wgchan = wgchan_find_remote(channels, remote);
        if (!wgchan) {
            wgchan = wgchan_find_unused(channels);
        }

        if (!wgchan) {
            DEBUG("wgchan channels exhausted\n");
            // send error?
            continue;
        }

        wgchan_handle_incoming(wgchan);
    }
}

/*****************/
/* example client side */
/* this assumes a lot of behind-the-scenes hooking up the sock udp to the event queue... */
main() {
    sock_udp_ep_t local = {0};
    sock_udp_rp_t remote = { .ipv6.addr = REMOTE_IP, .port = WGCHAN_PORT };

    sock_udp_create(&sock, local, remote, 0);
    event_queue_t queue = EVENT_QUEUE_INIT;
    sock_udp_attach(queue);

    wgchan_t wgchan;
    wgchan_init(&wgchan, &wgchan_id, wgchan_ops_udp, &sock);
    while(1) {
        int res = wgchan_send(wgchan, "foo", 3);
        if (res < 0) {
            // handle error
        }

        /* assume wgchan->ops->init set up wgchan->ops->handle_decrypted to post
         * an event to `queue` ...
         */
        event_t *event = event_queue_wait(queue);
        if (event) event->handler(event);
    }

#endif /* WGCHAN_H */
