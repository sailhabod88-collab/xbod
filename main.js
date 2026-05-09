// ===== المتغيرات العامة =====
let teachersData = { teachers: [] };
let currentTeacher = null;
let currentHistory = [];
let currentSection = null; // '2026', '2025', 'iraq'
let allTeachersData = {
    '2026': { teachers: [] },
    '2025': { teachers: [] },
    'iraq': { teachers: [] }
};

// ===== تشغيل التطبيق =====
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

// ===== تهيئة التطبيق =====
function initializeApp() {
    // عرض نافذة الاشتراك إذا لم يكن المستخدم مشتركاً
    // إخفاء نافذة الاشتراك إذا كان مشتركاً مسبقاً
    if (Storage.getSubscriptionStatus()) {
        hideSubscriptionModal();
    }
    // إذا لم يكن مشتركاً، النافذة ستظهر تلقائياً (display: flex افتراضياً)
    
    // تحميل جميع البيانات
    loadAllData();
    
    // إعداد أحداث النافذة المنبثقة
    setupModalEvents();
    
    // إعداد مشغل الفيديو
    VideoPlayer.init();
    
    // إضافة تأثيرات الصفحة
    addPageEffects();
}

// ===== تحميل جميع البيانات =====
async function loadAllData() {
    try {
        // تحميل بيانات 2026
        const response2026 = await fetch('./dataab26.json');
        if (response2026.ok) {
            allTeachersData['2026'] = await response2026.json();
        }
    } catch (error) {
        console.log('لم يتم العثور على ملف dataab26.json');
    }
    
    try {
        // تحميل بيانات 2025
        const response2025 = await fetch('./dataab25.json');
        if (response2025.ok) {
            allTeachersData['2025'] = await response2025.json();
        }
    } catch (error) {
        console.log('لم يتم العثور على ملف dataab25.json');
    }
    
    try {
        // تحميل بيانات العراق أكاديمي
        const responseIraq = await fetch('./dataiq25.json');
        if (responseIraq.ok) {
            allTeachersData['iraq'] = await responseIraq.json();
        }
    } catch (error) {
        console.log('لم يتم العثور على ملف dataiq25.json');
    }
}

// ===== نافذة الاشتراك =====
function showSubscriptionModal() {
    const modal = document.getElementById('subscriptionModal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function hideSubscriptionModal() {
    const modal = document.getElementById('subscriptionModal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// ===== إعداد أحداث النافذة المنبثقة =====
function setupModalEvents() {
    const subscribedBtn = document.getElementById('subscribed-btn');
    
    if (subscribedBtn) {
        subscribedBtn.addEventListener('click', function(e) {
            e.preventDefault();
            Storage.setSubscriptionStatus(true);
            hideSubscriptionModal();
            showNotification('تم تسجيل اشتراكك بنجاح! 🎉', 'success');
        });
    }
    
    // إغلاق النافذة بالنقر خارجها
    const modal = document.getElementById('subscriptionModal');
    if (modal) {
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                showNotification('يجب الاشتراك في القناة أولاً ⚠️', 'warning');
            }
        });
    }
}

// ===== تحميل قسم معين =====
function loadSection(section) {
    currentSection = section;
    teachersData = allTeachersData[section] || { teachers: [] };
    
    // تحديث عنوان الصفحة
    const titles = {
        '2026': { title: 'محاضرات 2026', subtitle: 'أحدث المحاضرات للعام الدراسي الجديد' },
        '2025': { title: 'محاضرات 2025', subtitle: 'محاضرات العام السابق كاملة' },
        'iraq': { title: 'العراق أكاديمي 2025', subtitle: 'محاضرات منصة العراق أكاديمي' }
    };
    
    document.getElementById('section-title').textContent = titles[section].title;
    document.getElementById('section-subtitle').textContent = titles[section].subtitle;
    
    currentHistory = ['home'];
    currentHistory.push('teachers');
    showPage('teachers-page');
    displayTeachers();
}

// ===== تحميل وعرض المدرسين =====
function loadTeachers() {
    if (!currentSection) return;
    currentHistory.push('teachers');
    showPage('teachers-page');
    displayTeachers();
}

// ===== عرض المدرسين =====
function displayTeachers() {
    const grid = document.getElementById('teachers-grid');
    
    if (!teachersData.teachers || teachersData.teachers.length === 0) {
        grid.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-inbox" style="font-size: 4rem; color: var(--gray-600); margin-bottom: 1rem;"></i>
                <h3 style="color: var(--gray-400);">لا توجد بيانات متاحة</h3>
                <p style="color: var(--gray-500);">سيتم إضافة المحاضرات قريباً</p>
            </div>
        `;
        return;
    }
    
    grid.innerHTML = teachersData.teachers.map(teacher => {
        const totalLectures = teacher.classes ? teacher.classes.reduce((total, cls) => 
            total + (cls.lectures ? cls.lectures.length : 0), 0) : 0;
        const completedLectures = teacher.classes ? teacher.classes.reduce((total, cls) => 
            total + (cls.lectures ? cls.lectures.filter(lecture => 
                Storage.isLectureCompleted(teacher.id, lecture.title)).length : 0), 0) : 0;
        
        return `
            <div class="teacher-card" onclick="loadTeacherClasses(${teacher.id})">
                <div class="teacher-image">
                    <img src="${teacher.image}" alt="${teacher.name}" 
                         onerror="this.src='https://ui-avatars.com/api/?name=${encodeURIComponent(teacher.name)}&background=6366f1&color=fff&size=200'">
                </div>
                <h3>${teacher.name}</h3>
                <p>${teacher.subject}</p>
                <div class="teacher-stats">
                    <div class="stat">
                        <span class="stat-number">${totalLectures}</span>
                        <span class="stat-label">محاضرة</span>
                    </div>
                    <div class="stat">
                        <span class="stat-number">${completedLectures}</span>
                        <span class="stat-label">مكتملة</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ===== فلترة المدرسين =====
function filterTeachers() {
    const searchTerm = document.getElementById('teacher-search').value.toLowerCase();
    const cards = document.querySelectorAll('.teacher-card');
    
    cards.forEach(card => {
        const name = card.querySelector('h3').textContent.toLowerCase();
        const subject = card.querySelector('p').textContent.toLowerCase();
        
        if (name.includes(searchTerm) || subject.includes(searchTerm)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

// ===== تحميل فصول المدرس =====
function loadTeacherClasses(teacherId) {
    currentTeacher = teachersData.teachers.find(t => t.id === teacherId);
    if (!currentTeacher) return;
    
    currentHistory.push('classes');
    showPage('classes-page');
    displayTeacherClasses();
}

// ===== عرض فصول المدرس =====
function displayTeacherClasses() {
    // تحديث الهيدر
    document.getElementById('teacher-name-header').innerHTML = currentTeacher.name;
    document.getElementById('teacher-subject-header').textContent = currentTeacher.subject;
    
    const headerImg = document.getElementById('teacher-image-header');
    headerImg.src = currentTeacher.image;
    headerImg.onerror = function() {
        this.src = `https://ui-avatars.com/api/?name=${encodeURIComponent(currentTeacher.name)}&background=6366f1&color=fff&size=200`;
    };
    
    const classesList = document.getElementById('classes-list');
    
    if (!currentTeacher.classes || currentTeacher.classes.length === 0) {
        classesList.innerHTML = `
            <div class="empty-state" style="text-align: center; padding: 3rem;">
                <i class="fas fa-folder-open" style="font-size: 4rem; color: var(--gray-600); margin-bottom: 1rem;"></i>
                <h3 style="color: var(--gray-400);">لا توجد محاضرات بعد</h3>
                <p style="color: var(--gray-500);">سيتم إضافة المحاضرات قريباً</p>
            </div>
        `;
        return;
    }
    
    classesList.innerHTML = currentTeacher.classes.map((classItem, classIndex) => {
        const lectures = classItem.lectures || [];
        const completedLectures = lectures.filter(lecture => 
            Storage.isLectureCompleted(currentTeacher.id, lecture.title)).length;
        const totalLectures = lectures.length;
        
        return `
            <div class="class-item">
                <div class="class-header" onclick="toggleClassDropdown(${classIndex})">
                    <div class="class-info">
                        <h3>${classItem.name}</h3>
                        <div class="class-progress">
                            <span><i class="fas fa-check-circle"></i> ${completedLectures} مكتملة</span>
                            <span><i class="fas fa-video"></i> ${totalLectures} محاضرة</span>
                        </div>
                    </div>
                    <div class="expand-icon">
                        <i class="fas fa-chevron-down"></i>
                    </div>
                </div>
                <div class="lectures-dropdown">
                    <div class="lectures-list">
                        ${lectures.map((lecture, lectureIndex) => {
                            const isCompleted = Storage.isLectureCompleted(currentTeacher.id, lecture.title);
                            return `
                                <div class="lecture-item">
                                    <div class="completion-checkbox ${isCompleted ? 'completed' : ''}" 
                                         onclick="event.stopPropagation(); toggleLectureCompletion(${classIndex}, ${lectureIndex})">
                                    </div>
                                    <div class="lecture-info" onclick="playLecture(${classIndex}, ${lectureIndex})">
                                        <h4>${lecture.title}</h4>
                                        <p>${lecture.description || 'محاضرة تعليمية'}</p>
                                    </div>
                                    <button class="play-button" onclick="playLecture(${classIndex}, ${lectureIndex})">
                                        <i class="fas fa-play"></i> تشغيل
                                    </button>
                                </div>
                            `;
                        }).join('')}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// ===== تبديل القائمة المنسدلة للفصل =====
function toggleClassDropdown(classIndex) {
    const classItems = document.querySelectorAll('.class-item');
    classItems[classIndex].classList.toggle('expanded');
}

// ===== تبديل حالة إكمال المحاضرة =====
function toggleLectureCompletion(classIndex, lectureIndex) {
    const lecture = currentTeacher.classes[classIndex].lectures[lectureIndex];
    const isCompleted = Storage.isLectureCompleted(currentTeacher.id, lecture.title);
    
    if (isCompleted) {
        Storage.removeLectureCompletion(currentTeacher.id, lecture.title);
    } else {
        Storage.markLectureCompleted(currentTeacher.id, lecture.title);
    }
    
    displayTeacherClasses();
    
    const message = isCompleted ? 'تم إلغاء التمييز' : 'تم تمييز المحاضرة كمكتملة ✓';
    showNotification(message, isCompleted ? 'info' : 'success');
}

// ===== تشغيل المحاضرة =====
function playLecture(classIndex, lectureIndex) {
    const lecture = currentTeacher.classes[classIndex].lectures[lectureIndex];
    currentHistory.push('player');
    showPage('player-page');
    
    // تحديد نوع التشغيل حسب القسم
    const useProxy = currentSection !== 'iraq';
    VideoPlayer.loadVideo(lecture, useProxy);
}

// ===== عرض الصفحة =====
function showPage(pageId) {
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });
    
    document.getElementById(pageId).classList.add('active');
    
    const backButton = document.getElementById('back-button');
    if (pageId === 'home-page') {
        backButton.style.display = 'none';
        currentSection = null;
    } else {
        backButton.style.display = 'block';
    }
    
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ===== العودة للصفحة الرئيسية =====
function goHome() {
    currentHistory = [];
    currentSection = null;
    showPage('home-page');
}

// ===== العودة للصفحة السابقة =====
function goBack() {
    currentHistory.pop();
    
    if (currentHistory.length === 0 || currentHistory[currentHistory.length - 1] === 'home') {
        goHome();
        return;
    }
    
    const previousPage = currentHistory[currentHistory.length - 1];
    
    switch (previousPage) {
        case 'teachers':
            showPage('teachers-page');
            break;
        case 'classes':
            showPage('classes-page');
            displayTeacherClasses();
            break;
        case 'player':
            showPage('player-page');
            break;
        default:
            goHome();
    }
}

// ===== القائمة المتنقلة =====
function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    menu.classList.toggle('active');
}

// ===== عرض الإشعارات =====
function showNotification(message, type = 'info') {
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(n => n.remove());
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    
    const colors = {
        success: 'linear-gradient(135deg, #22c55e 0%, #16a34a 100%)',
        error: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
        warning: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
        info: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)'
    };
    
    notification.innerHTML = `
        <i class="fas fa-${icons[type]}"></i>
        <span>${message}</span>
    `;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type]};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 12px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        z-index: 1001;
        display: flex;
        align-items: center;
        gap: 10px;
        font-family: 'Cairo', sans-serif;
        font-weight: 500;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
        max-width: 400px;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 100);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100%)';
        setTimeout(() => notification.remove(), 400);
    }, 3000);
}

// ===== تأثيرات الصفحة =====
function addPageEffects() {
    // تأثير التمرير على الهيدر
    window.addEventListener('scroll', () => {
        const header = document.querySelector('.header');
        if (window.scrollY > 50) {
            header.style.background = 'rgba(15, 23, 42, 0.95)';
        } else {
            header.style.background = 'rgba(15, 23, 42, 0.8)';
        }
    });
    
    // إغلاق القائمة المتنقلة عند النقر خارجها
    document.addEventListener('click', (e) => {
        const mobileMenu = document.getElementById('mobile-menu');
        const mobileBtn = document.querySelector('.mobile-menu-btn');
        
        if (!mobileMenu.contains(e.target) && !mobileBtn.contains(e.target)) {
            mobileMenu.classList.remove('active');
        }
    });
}

// ===== معالجة الأخطاء العامة =====
window.addEventListener('error', function(e) {
    console.error('خطأ في التطبيق:', e.error);
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('خطأ في Promise:', e.reason);
});
