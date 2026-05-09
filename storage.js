// إدارة التخزين المحلي
class LocalStorage {
    constructor() {
        this.prefix = 'hydrogen_';
    }

    // حفظ حالة الاشتراك
    setSubscriptionStatus(status) {
        localStorage.setItem(this.prefix + 'subscribed', JSON.stringify(status));
    }

    // الحصول على حالة الاشتراك
    getSubscriptionStatus() {
        const status = localStorage.getItem(this.prefix + 'subscribed');
        return status ? JSON.parse(status) : false;
    }

    // تمييز محاضرة كمكتملة
    markLectureCompleted(teacherId, lectureTitle) {
        const completedLectures = this.getCompletedLectures(teacherId);
        if (!completedLectures.includes(lectureTitle)) {
            completedLectures.push(lectureTitle);
            this.saveCompletedLectures(teacherId, completedLectures);
        }
    }

    // إزالة تمييز المحاضرة
    removeLectureCompletion(teacherId, lectureTitle) {
        const completedLectures = this.getCompletedLectures(teacherId);
        const index = completedLectures.indexOf(lectureTitle);
        if (index > -1) {
            completedLectures.splice(index, 1);
            this.saveCompletedLectures(teacherId, completedLectures);
        }
    }

    // التحقق من إكمال المحاضرة
    isLectureCompleted(teacherId, lectureTitle) {
        const completedLectures = this.getCompletedLectures(teacherId);
        return completedLectures.includes(lectureTitle);
    }

    // الحصول على المحاضرات المكتملة للمدرس
    getCompletedLectures(teacherId) {
        const key = this.prefix + 'completed_' + teacherId;
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : [];
    }

    // حفظ المحاضرات المكتملة
    saveCompletedLectures(teacherId, lectures) {
        const key = this.prefix + 'completed_' + teacherId;
        localStorage.setItem(key, JSON.stringify(lectures));
    }

    // حفظ تقدم الفيديو
    saveVideoProgress(lectureId, currentTime, duration) {
        const progress = {
            currentTime: currentTime,
            duration: duration,
            timestamp: Date.now()
        };
        localStorage.setItem(this.prefix + 'progress_' + lectureId, JSON.stringify(progress));
    }

    // الحصول على تقدم الفيديو
    getVideoProgress(lectureId) {
        const data = localStorage.getItem(this.prefix + 'progress_' + lectureId);
        return data ? JSON.parse(data) : null;
    }

    // حفظ إعدادات المشغل
    savePlayerSettings(settings) {
        localStorage.setItem(this.prefix + 'player_settings', JSON.stringify(settings));
    }

    // الحصول على إعدادات المشغل
    getPlayerSettings() {
        const data = localStorage.getItem(this.prefix + 'player_settings');
        return data ? JSON.parse(data) : {
            quality: '480',
            volume: 1,
            playbackRate: 1
        };
    }

    // مسح جميع البيانات
    clearAll() {
        const keys = Object.keys(localStorage);
        keys.forEach(key => {
            if (key.startsWith(this.prefix)) {
                localStorage.removeItem(key);
            }
        });
    }

    // الحصول على إحصائيات الاستخدام
    getUsageStats() {
        const completedLectures = Object.keys(localStorage)
            .filter(key => key.includes('completed_'))
            .reduce((total, key) => {
                const lectures = JSON.parse(localStorage.getItem(key) || '[]');
                return total + lectures.length;
            }, 0);

        const watchedTime = Object.keys(localStorage)
            .filter(key => key.includes('progress_'))
            .reduce((total, key) => {
                const progress = JSON.parse(localStorage.getItem(key) || '{}');
                return total + (progress.currentTime || 0);
            }, 0);

        return {
            completedLectures,
            watchedTime: Math.round(watchedTime / 60), // بالدقائق
            lastAccess: Date.now()
        };
    }
}

// إنشاء مثيل من كلاس التخزين
const Storage = new LocalStorage();

// تصدير للاستخدام في الملفات الأخرى
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Storage;
}
