(() => {
    if (!window.io) return;

    const socket = window.familyPresenceSocket || (window.familyPresenceSocket = window.io());
    const heartbeat = () => {
        if (socket.connected) socket.emit("presence_heartbeat");
    };

    socket.on("connect", heartbeat);
    window.setInterval(heartbeat, 30000);
})();
