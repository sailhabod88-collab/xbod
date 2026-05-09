// ===== مشغل الفيديو المتقدم =====
class VideoPlayerClass {
    constructor() {
        this.iframe = null;
        this.video = null;
        this.currentLecture = null;
        this.loadingSpinner = null;
        this.proxyUrl = 'https://videoiq.duckdns.org/';
        this.useProxy = true;
    }

    // ===== تهيئة المشغل =====
    init() {
        this.iframe = document.getElementById('video-iframe');
        this.video = document.getElementById('video-player');
        this.loadingSpinner = document.getElementById('loading-spinner');
        
        if (this.iframe) {
            this.iframe.addEventListener('load', () => {
                this.hideLoading();
            });
        }
        
        if (this.video) {
            this.video.addEventListener('loadeddata', () => {
                this.hideLoading();
            });
            
            this.video.addEventListener('canplay', () => {
                this.hideLoading();
            });
            
            this.video.addEventListener('waiting', () => {
                // فقط إذا كان هناك src
                if (this.video.src && this.video.src !== '') {
                    this.showLoading();
                }
            });
            
            this.video.addEventListener('playing', () => {
                this.hideLoading();
            });
            
            this.video.addEventListener('error', (e) => {
                // فقط إذا كان هناك src وكان video ظاهراً
                if (this.video.src && this.video.src !== '' && this.video.style.display !== 'none') {
                    console.error('خطأ في تشغيل الفيديو:', e);
                    this.hideLoading();
                    this.showVideoError();
                }
            });
        }
    }

    // ===== تحميل الفيديو =====
    loadVideo(lecture, useProxy = true) {
        if (!lecture || !lecture.url) {
            console.error('بيانات المحاضرة غير صحيحة');
            return;
        }

        this.currentLecture = lecture;
        this.useProxy = useProxy;
        this.showLoading();

        // تحديث عنوان المحاضرة
        const titleElement = document.getElementById('current-lecture-title');
        if (titleElement) {
            titleElement.textContent = lecture.title;
        }

        // تحديد نوع التشغيل
        if (useProxy) {
            // استخدام iframe مع البروكسي
            this.playWithProxy(lecture.url);
        } else {
            // تشغيل مباشر بدون بروكسي
            this.playDirect(lecture.url);
        }
    }

    // ===== تشغيل مع البروكسي (iframe) =====
    playWithProxy(originalUrl) {
        // إخفاء video وإظهار iframe
        if (this.video) {
            this.video.style.display = 'none';
            this.video.src = '';
        }
        if (this.iframe) {
            this.iframe.style.display = 'block';
        }

        // بناء رابط البروكسي
        const proxyUrl = this.buildProxyUrl(originalUrl);
        
        console.log('🎬 Original URL:', originalUrl);
        console.log('🔗 Proxy URL:', proxyUrl);
        
        // تحميل في iframe
        if (this.iframe) {
            this.iframe.src = proxyUrl;
        }
    }

    // ===== تشغيل مباشر بدون بروكسي (video) =====
    playDirect(url) {
        // إخفاء iframe وإظهار video
        if (this.iframe) {
            this.iframe.style.display = 'none';
            this.iframe.src = '';
        }
        if (this.video) {
            this.video.style.display = 'block';
        }

        console.log('🎬 Direct URL:', url);
        
        // تحميل الفيديو مباشرة
        if (this.video) {
            this.video.src = url;
            this.video.load();
        }
    }

    // ===== بناء رابط البروكسي =====
    buildProxyUrl(originalUrl) {
        let url = originalUrl.trim();
        
        // استخراج video ID من روابط embed
        // النمط: https://iframe.mediadelivery.net/embed/215061/7f2873a8-c450-4db3-819a-1cfc518c23f8
        const embedMatch = url.match(/embed\/\d+\/([a-f0-9-]{36})/i);
        if (embedMatch) {
            return this.proxyUrl + embedMatch[1];
        }
        
        // روابط b-cdn.net
        // النمط: https://vz-b26dd76f-dc1.b-cdn.net/64abbd52-68ad-45fd-8631-146ede3b35c3
        const cdnMatch = url.match(/b-cdn\.net\/([a-f0-9-]{36})/i);
        if (cdnMatch) {
            return this.proxyUrl + cdnMatch[1];
        }
        
        // روابط m3u8
        const m3u8Match = url.match(/embed\/\d+\/([a-f0-9-]{36})\/\d+p\/video\.m3u8/i);
        if (m3u8Match) {
            return this.proxyUrl + m3u8Match[1];
        }
        
        // إذا لم يتطابق، أعد الرابط كما هو
        console.warn('⚠️ رابط غير معروف:', url);
        return url;
    }

    // ===== إظهار شاشة التحميل =====
    showLoading() {
        if (this.loadingSpinner) {
            this.loadingSpinner.style.display = 'flex';
        }
    }

    // ===== إخفاء شاشة التحميل =====
    hideLoading() {
        if (this.loadingSpinner) {
            this.loadingSpinner.style.display = 'none';
        }
    }

    // ===== عرض خطأ الفيديو =====
    showVideoError() {
        const videoWrapper = document.querySelector('.video-wrapper');
        if (!videoWrapper) return;

        // إزالة أي رسائل خطأ سابقة
        const existing = videoWrapper.querySelector('.video-error');
        if (existing) existing.remove();

        const errorDiv = document.createElement('div');
        errorDiv.className = 'video-error';
        errorDiv.innerHTML = `
            <div style="
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                background: rgba(0, 0, 0, 0.95);
                color: white;
                text-align: center;
                padding: 2rem;
                z-index: 15;
            ">
                <i class="fas fa-exclamation-triangle" style="font-size: 3.5rem; color: #f59e0b; margin-bottom: 1.5rem;"></i>
                <h3 style="font-size: 1.25rem; margin-bottom: 0.75rem;">حدث خطأ في تحميل الفيديو</h3>
                <p style="color: rgba(255,255,255,0.7); margin-bottom: 1.5rem;">يرجى المحاولة مرة أخرى لاحقاً</p>
                <button onclick="this.closest('.video-error').remove()" style="
                    padding: 0.75rem 2rem;
                    background: #ef4444;
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 1rem;
                    cursor: pointer;
                    font-family: inherit;
                ">
                    إغلاق
                </button>
            </div>
        `;
        
        videoWrapper.appendChild(errorDiv);
        
        setTimeout(() => {
            if (errorDiv.parentElement) {
                errorDiv.remove();
            }
        }, 15000);
    }

    // ===== تنظيف المشغل =====
    cleanup() {
        if (this.iframe) {
            this.iframe.src = '';
            this.iframe.style.display = 'none';
        }
        if (this.video) {
            this.video.pause();
            this.video.src = '';
            this.video.style.display = 'none';
        }
        this.currentLecture = null;
        this.hideLoading();
        
        // إزالة رسائل الخطأ
        const errors = document.querySelectorAll('.video-error');
        errors.forEach(e => e.remove());
    }

    // ===== معلومات المشغل =====
    getPlayerInfo() {
        return {
            lecture: this.currentLecture?.title,
            useProxy: this.useProxy,
            type: this.useProxy ? 'iframe' : 'video'
        };
    }
}

// ===== إنشاء المشغل =====
const VideoPlayer = new VideoPlayerClass();

// ===== تصدير =====
if (typeof module !== 'undefined' && module.exports) {
    module.exports = VideoPlayer;
}
