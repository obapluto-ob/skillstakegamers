// Real WebRTC Streaming Implementation
class RealStreamingEngine {
    constructor() {
        this.localStream = null;
        this.peerConnections = new Map();
        this.streamId = null;
        this.isStreaming = false;
        this.viewers = new Set();
        
        // WebRTC configuration
        this.rtcConfig = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };
    }

    async startStream(streamTitle, streamType = 'screen') {
        try {
            // Get real media stream
            if (streamType === 'screen') {
                this.localStream = await navigator.mediaDevices.getDisplayMedia({
                    video: { mediaSource: 'screen', width: 1920, height: 1080 },
                    audio: true
                });
            } else {
                this.localStream = await navigator.mediaDevices.getUserMedia({
                    video: true,
                    audio: true
                });
            }

            // Create stream in database
            const response = await fetch('/api/create_real_stream', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: streamTitle,
                    type: streamType,
                    competition: true
                })
            });

            const data = await response.json();
            if (data.success) {
                this.streamId = data.stream_id;
                this.isStreaming = true;
                
                // Start WebSocket for real-time communication
                this.initWebSocket();
                
                // Display local stream
                this.displayLocalStream();
                
                // Start earnings timer
                this.startEarningsTimer();
                
                return { success: true, streamId: this.streamId };
            }
        } catch (error) {
            console.error('Stream start failed:', error);
            return { success: false, error: error.message };
        }
    }

    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${protocol}//${window.location.host}/ws/stream/${this.streamId}`);
        
        this.ws.onmessage = async (event) => {
            const message = JSON.parse(event.data);
            
            switch (message.type) {
                case 'viewer_joined':
                    await this.handleViewerJoined(message.viewerId);
                    break;
                case 'viewer_left':
                    this.handleViewerLeft(message.viewerId);
                    break;
                case 'ice_candidate':
                    await this.handleIceCandidate(message);
                    break;
                case 'answer':
                    await this.handleAnswer(message);
                    break;
            }
        };
    }

    async handleViewerJoined(viewerId) {
        // Create peer connection for new viewer
        const peerConnection = new RTCPeerConnection(this.rtcConfig);
        this.peerConnections.set(viewerId, peerConnection);
        
        // Add local stream to peer connection
        this.localStream.getTracks().forEach(track => {
            peerConnection.addTrack(track, this.localStream);
        });

        // Handle ICE candidates
        peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.ws.send(JSON.stringify({
                    type: 'ice_candidate',
                    candidate: event.candidate,
                    viewerId: viewerId
                }));
            }
        };

        // Create offer for viewer
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);
        
        this.ws.send(JSON.stringify({
            type: 'offer',
            offer: offer,
            viewerId: viewerId
        }));

        this.viewers.add(viewerId);
        this.updateViewerCount();
    }

    async handleAnswer(message) {
        const peerConnection = this.peerConnections.get(message.viewerId);
        if (peerConnection) {
            await peerConnection.setRemoteDescription(message.answer);
        }
    }

    async handleIceCandidate(message) {
        const peerConnection = this.peerConnections.get(message.viewerId);
        if (peerConnection) {
            await peerConnection.addIceCandidate(message.candidate);
        }
    }

    handleViewerLeft(viewerId) {
        const peerConnection = this.peerConnections.get(viewerId);
        if (peerConnection) {
            peerConnection.close();
            this.peerConnections.delete(viewerId);
        }
        this.viewers.delete(viewerId);
        this.updateViewerCount();
    }

    displayLocalStream() {
        const previewArea = document.getElementById('previewArea');
        previewArea.innerHTML = '';
        
        const video = document.createElement('video');
        video.srcObject = this.localStream;
        video.autoplay = true;
        video.muted = true;
        video.style.width = '100%';
        video.style.height = '100%';
        video.style.objectFit = 'cover';
        video.style.borderRadius = '15px';
        
        previewArea.appendChild(video);
        
        // Add live indicator with SVG
        const liveIndicator = document.createElement('div');
        liveIndicator.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" fill="#dc3545"/><circle cx="12" cy="12" r="3" fill="white"/></svg> LIVE';
        liveIndicator.style.cssText = `
            position: absolute;
            top: 15px;
            left: 15px;
            background: #dc3545;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            z-index: 10;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        `;
        previewArea.style.position = 'relative';
        previewArea.appendChild(liveIndicator);
        
        // Add viewer count with enhanced monetization display
        const viewerCount = document.createElement('div');
        viewerCount.id = 'viewerCount';
        viewerCount.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M16 21V19C16 16.79 14.21 15 12 15H5C2.79 15 1 16.79 1 19V21M12.5 7C12.5 9.21 10.71 11 8.5 11S4.5 9.21 4.5 7S6.29 3 8.5 3S12.5 4.79 12.5 7ZM20 8V6M23 7H17" stroke="white" stroke-width="2"/> 0 viewers';
        viewerCount.style.cssText = `
            position: absolute;
            top: 15px;
            right: 15px;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 15px;
            z-index: 10;
        `;
        previewArea.appendChild(viewerCount);
        
        // Add earnings tracker
        const earningsTracker = document.createElement('div');
        earningsTracker.id = 'earningsTracker';
        earningsTracker.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" stroke="#ffc107" stroke-width="2"/><path d="M12 6V18M9 9H15M9 15H15" stroke="#ffc107" stroke-width="2"/></svg> KSh 0 earned';
        earningsTracker.style.cssText = `
            position: absolute;
            bottom: 15px;
            left: 15px;
            background: rgba(255,193,7,0.9);
            color: black;
            padding: 0.5rem 1rem;
            border-radius: 15px;
            font-weight: bold;
            z-index: 10;
        `;
        previewArea.appendChild(earningsTracker);
    }

    updateViewerCount() {
        const viewerCountEl = document.getElementById('viewerCount');
        if (viewerCountEl) {
            viewerCountEl.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M16 21V19C16 16.79 14.21 15 12 15H5C2.79 15 1 16.79 1 19V21M12.5 7C12.5 9.21 10.71 11 8.5 11S4.5 9.21 4.5 7S6.29 3 8.5 3S12.5 4.79 12.5 7ZM20 8V6M23 7H17" stroke="white" stroke-width="2"/> ${this.viewers.size} viewers`;
        }
        
        // Update earnings display
        this.updateEarningsDisplay();
        
        // Update database
        fetch(`/api/update_viewers/${this.streamId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ count: this.viewers.size })
        });
    }

    async stopStream() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
        }
        
        // Close all peer connections
        this.peerConnections.forEach(pc => pc.close());
        this.peerConnections.clear();
        
        if (this.ws) {
            this.ws.close();
        }
        
        // Update database
        if (this.streamId) {
            await fetch(`/api/stop_stream/${this.streamId}`, {
                method: 'POST'
            });
        }
        
        this.isStreaming = false;
        this.viewers.clear();
    }
    
    updateEarningsDisplay() {
        const earningsEl = document.getElementById('earningsTracker');
        if (earningsEl && this.isStreaming) {
            const streamStartTime = this.streamStartTime || Date.now();
            const hoursStreamed = (Date.now() - streamStartTime) / (1000 * 60 * 60);
            
            // Enhanced earnings calculation
            const baseEarnings = hoursStreamed * 15; // KSh 15/hour
            const viewerBonus = this.viewers.size * hoursStreamed * 5; // KSh 5 per viewer/hour
            const performanceBonus = Math.min(200, this.viewers.size * 10); // Up to KSh 200
            const sponsorBonus = this.viewers.size >= 10 ? 50 : 0; // KSh 50 for 10+ viewers
            
            const totalEarnings = baseEarnings + viewerBonus + performanceBonus + sponsorBonus;
            
            earningsEl.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" stroke="#ffc107" stroke-width="2"/><path d="M12 6V18M9 9H15M9 15H15" stroke="#ffc107" stroke-width="2"/></svg> KSh ${Math.round(totalEarnings)} earned`;
        }
    }
    
    startEarningsTimer() {
        this.streamStartTime = Date.now();
        setInterval(() => {
            this.updateEarningsDisplay();
        }, 10000); // Update every 10 seconds
    }
}

// Real Stream Viewer
class RealStreamViewer {
    constructor() {
        this.peerConnection = null;
        this.ws = null;
        this.streamId = null;
    }

    async joinStream(streamId) {
        this.streamId = streamId;
        
        // Initialize WebSocket
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${protocol}//${window.location.host}/ws/viewer/${streamId}`);
        
        this.ws.onmessage = async (event) => {
            const message = JSON.parse(event.data);
            
            switch (message.type) {
                case 'offer':
                    await this.handleOffer(message.offer);
                    break;
                case 'ice_candidate':
                    await this.handleIceCandidate(message.candidate);
                    break;
            }
        };
        
        // Join as viewer
        this.ws.onopen = () => {
            this.ws.send(JSON.stringify({ type: 'join_viewer' }));
        };
    }

    async handleOffer(offer) {
        this.peerConnection = new RTCPeerConnection({
            iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });
        
        // Handle incoming stream
        this.peerConnection.ontrack = (event) => {
            const video = document.getElementById('streamVideo');
            if (video) {
                video.srcObject = event.streams[0];
            }
        };
        
        // Handle ICE candidates
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.ws.send(JSON.stringify({
                    type: 'ice_candidate',
                    candidate: event.candidate
                }));
            }
        };
        
        await this.peerConnection.setRemoteDescription(offer);
        const answer = await this.peerConnection.createAnswer();
        await this.peerConnection.setLocalDescription(answer);
        
        this.ws.send(JSON.stringify({
            type: 'answer',
            answer: answer
        }));
    }

    async handleIceCandidate(candidate) {
        if (this.peerConnection) {
            await this.peerConnection.addIceCandidate(candidate);
        }
    }
}

// Global instances - initialize when needed
window.RealStreamingEngine = RealStreamingEngine;
window.RealStreamViewer = RealStreamViewer;
window.streamingEngine = null;
window.streamViewer = null;