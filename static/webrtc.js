// WebRTC Real Video Streaming
class RealStreamManager {
    constructor(streamId, isOwner) {
        this.streamId = streamId;
        this.isOwner = isOwner;
        this.localStream = null;
        this.peerConnection = null;
        this.socket = null;
        this.remoteVideo = document.getElementById('remoteVideo');
        this.localVideo = document.getElementById('localVideo');
        
        if (!this.remoteVideo || !this.localVideo) {
            console.warn('Video elements not found in DOM');
        }
        
        this.initializeWebRTC();
    }
    
    async initializeWebRTC() {
        // WebRTC configuration
        this.peerConnection = new RTCPeerConnection({
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        });
        
        // Handle remote stream
        this.peerConnection.ontrack = (event) => {
            if (this.remoteVideo) {
                this.remoteVideo.srcObject = event.streams[0];
                console.log('Remote stream received');
            }
        };
        
        // Handle ICE candidates
        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.sendSignalingMessage({
                    type: 'ice-candidate',
                    candidate: event.candidate
                });
            }
        };
        
        if (this.isOwner) {
            await this.startStreaming();
        } else {
            this.connectAsViewer();
        }
    }
    
    async startStreaming() {
        try {
            // Get user media (camera + microphone)
            this.localStream = await navigator.mediaDevices.getUserMedia({
                video: { width: 1280, height: 720 },
                audio: true
            });
            
            if (this.localVideo) {
                this.localVideo.srcObject = this.localStream;
            }
            
            // Add tracks to peer connection
            this.localStream.getTracks().forEach(track => {
                this.peerConnection.addTrack(track, this.localStream);
            });
            
            console.log('Streaming started with camera');
            
        } catch (error) {
            console.error('Failed to start camera:', error);
            // Fallback to screen sharing
            await this.startScreenShare();
        }
    }
    
    async startScreenShare() {
        try {
            this.localStream = await navigator.mediaDevices.getDisplayMedia({
                video: { width: 1920, height: 1080 },
                audio: true
            });
            
            if (this.localVideo) {
                this.localVideo.srcObject = this.localStream;
            }
            
            // Remove existing tracks before adding new ones
            this.peerConnection.getSenders().forEach(sender => {
                if (sender.track) {
                    this.peerConnection.removeTrack(sender);
                }
            });
            
            // Add tracks to peer connection
            this.localStream.getTracks().forEach(track => {
                this.peerConnection.addTrack(track, this.localStream);
            });
            
            console.log('Screen sharing started');
            
        } catch (error) {
            console.error('Failed to start screen share:', error);
        }
    }
    
    connectAsViewer() {
        // Viewer connects to receive stream
        console.log('Connecting as viewer to stream', this.streamId);
        
        // Request stream from owner
        this.sendSignalingMessage({
            type: 'request-stream',
            streamId: this.streamId
        });
    }
    
    sendSignalingMessage(message) {
        // Get CSRF token from meta tag or cookie
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || 'no-token';
        
        // Send signaling through your Flask backend with CSRF protection
        fetch('/webrtc_signal', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                streamId: this.streamId,
                message: message,
                _token: csrfToken
            })
        }).catch(err => console.error('Signaling failed:', err));
    }
    
    async handleSignalingMessage(message) {
        try {
            switch (message.type) {
                case 'offer':
                    await this.handleOffer(message.offer);
                    break;
                case 'answer':
                    await this.handleAnswer(message.answer);
                    break;
                case 'ice-candidate':
                    await this.handleIceCandidate(message.candidate);
                    break;
                case 'request-stream':
                    if (this.isOwner) {
                        await this.createOffer();
                    }
                    break;
            }
        } catch (error) {
            console.error('WebRTC signaling error:', error);
        }
    }
    
    async createOffer() {
        try {
            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);
            
            this.sendSignalingMessage({
                type: 'offer',
                offer: offer
            });
        } catch (error) {
            console.error('WebRTC offer creation error:', error);
        }
    }
    
    async handleOffer(offer) {
        await this.peerConnection.setRemoteDescription(offer);
        const answer = await this.peerConnection.createAnswer();
        await this.peerConnection.setLocalDescription(answer);
        
        this.sendSignalingMessage({
            type: 'answer',
            answer: answer
        });
    }
    
    async handleAnswer(answer) {
        try {
            await this.peerConnection.setRemoteDescription(answer);
        } catch (error) {
            console.error('Error handling answer:', error);
        }
    }
    
    async handleIceCandidate(candidate) {
        try {
            await this.peerConnection.addIceCandidate(candidate);
        } catch (error) {
            console.error('Error handling ICE candidate:', error);
        }
    }
    
    stopStreaming() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
        }
        if (this.peerConnection) {
            this.peerConnection.close();
        }
    }
}

// Initialize real streaming
window.initRealStreaming = function(streamId, isOwner) {
    return new RealStreamManager(streamId, isOwner);
};