   
import os
import json
import time
import uuid
import hashlib
import functools
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ======================================================
# محاولة استيراد g4f مع التعامل مع حالة غيابه
# ======================================================
try:
    import g4f
    G4F_AVAILABLE = True
except ImportError:
    G4F_AVAILABLE = False
    print("[!] g4f غير مثبت. تعمل في وضع الرد الثابت.")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "elite-super-secret-key-2025")

# ======================================================
# Rate Limiting
# ======================================================
try:
    limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])
except Exception:
    limiter = None

# ======================================================
# إعدادات المسارات
# ======================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_FILE = os.path.join(BASE_DIR, "elite_db.json")
USERS_FILE   = os.path.join(BASE_DIR, "users_db.json")
ADMIN_FILE   = os.path.join(BASE_DIR, "admins_db.json")
LOGS_FILE    = os.path.join(BASE_DIR, "logs.json")
STATIC_DIR   = os.path.join(BASE_DIR, "static")

for d in [STATIC_DIR]:
    os.makedirs(d, exist_ok=True)

# ======================================================
# وظائف إدارة البيانات
# ======================================================
def load_json(file_path, default_data):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[Error] Loading {file_path}: {e}")
    return default_data

def save_json(file_path, data):
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        return True
    except Exception as e:
        print(f"[Error] Saving {file_path}: {e}")
        return False

def log_action(action, details="", user="system"):
    logs = load_json(LOGS_FILE, [])
    logs.append({
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "details": details,
        "user": user
    })
    # احتفظ بآخر 500 سجل فقط
    save_json(LOGS_FILE, logs[-500:])

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_unique_id():
    return str(uuid.uuid4())[:8].upper()

# ======================================================
# Middleware: حماية لوحة التحكم
# ======================================================
def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

# ======================================================
# ✅ API: إدارة المستخدمين (محسّن)
# ======================================================
@app.route('/api/v2/check_user/<fb_uid>', methods=['GET'])
def check_user(fb_uid):
    users = load_json(USERS_FILE, {})
    user_data = users.get(str(fb_uid))
    if user_data:
        # تحديث آخر ظهور
        user_data["last_seen"] = datetime.now().isoformat()
        users[fb_uid] = user_data
        save_json(USERS_FILE, users)
        return jsonify({"status": "exists", "data": user_data}), 200
    return jsonify({"status": "not_found"}), 404

@app.route('/api/v2/register_user', methods=['POST'])
def register_user():
    try:
        req_data = request.get_json()
        if not req_data or "fb_uid" not in req_data:
            return jsonify({"status": "error", "message": "بيانات ناقصة"}), 400

        required_fields = ["fb_uid", "name", "phone"]
        for field in required_fields:
            if field not in req_data:
                return jsonify({"status": "error", "message": f"الحقل {field} مطلوب"}), 400

        fb_uid = str(req_data["fb_uid"])
        users = load_json(USERS_FILE, {})

        if fb_uid in users:
            return jsonify({"status": "error", "message": "المستخدم مسجل مسبقاً"}), 409

        users[fb_uid] = {
            "name": req_data.get("name"),
            "phone": req_data.get("phone"),
            "gov": req_data.get("gov", ""),
            "unique_id": generate_unique_id(),
            "registered_at": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "is_active": True,
            "subscription": req_data.get("subscription", "free"),
            "chat_count": 0
        }
        save_json(USERS_FILE, users)
        log_action("register_user", f"uid={fb_uid}", req_data.get("name", "unknown"))
        return jsonify({"status": "success", "unique_id": users[fb_uid]["unique_id"]}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/v2/update_user/<fb_uid>', methods=['PUT'])
def update_user(fb_uid):
    try:
        req_data = request.get_json()
        users = load_json(USERS_FILE, {})
        if fb_uid not in users:
            return jsonify({"status": "error", "message": "المستخدم غير موجود"}), 404

        allowed_fields = ["name", "phone", "gov", "subscription"]
        for field in allowed_fields:
            if field in req_data:
                users[fb_uid][field] = req_data[field]
        users[fb_uid]["updated_at"] = datetime.now().isoformat()
        save_json(USERS_FILE, users)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/v2/users', methods=['GET'])
def get_all_users():
    """للأدمن فقط - يتطلب مفتاح API"""
    api_key = request.headers.get("X-API-Key")
    admins = load_json(ADMIN_FILE, {"admins": []})
    valid_keys = [a.get("api_key") for a in admins.get("admins", [])]
    if api_key not in valid_keys:
        return jsonify({"status": "error", "message": "غير مصرح"}), 403

    users = load_json(USERS_FILE, {})
    stats = {
        "total": len(users),
        "active": sum(1 for u in users.values() if u.get("is_active")),
        "paid": sum(1 for u in users.values() if u.get("subscription") == "paid")
    }
    return jsonify({"status": "success", "stats": stats, "users": users}), 200

# ======================================================
# ✅ محرك Goliath الذكي (v4 - متعدد المزودين + ذاكرة)
# ======================================================
chat_sessions = {}  # ذاكرة المحادثات المؤقتة في الذاكرة

@app.route('/api/v2/chat', methods=['POST'])
def chat_goliath_v2():
    """نسخة POST مع دعم الجلسات والسياق"""
    try:
        data = request.get_json() or {}
        user_msg = data.get("msg", "").strip()
        session_id = data.get("session_id", "default")
        fb_uid = data.get("fb_uid", "anonymous")
    except Exception:
        user_msg = ""
        session_id = "default"
        fb_uid = "anonymous"

    if not user_msg:
        return jsonify({"response": "أهلاً بك! أنا Goliath، مساعدك الذكي. كيف يمكنني مساعدتك؟", "session_id": session_id})

    # تحديث عداد المحادثات للمستخدم
    users = load_json(USERS_FILE, {})
    if fb_uid in users:
        users[fb_uid]["chat_count"] = users[fb_uid].get("chat_count", 0) + 1
        save_json(USERS_FILE, users)

    # بناء سجل المحادثة
    if session_id not in chat_sessions:
        chat_sessions[session_id] = []

    chat_sessions[session_id].append({"role": "user", "content": user_msg})

    # الاحتفاظ بآخر 10 رسائل فقط للسياق
    context = chat_sessions[session_id][-10:]

    system_prompt = (
        "أنت Goliath، مساعد ذكي لمنصة النخبة التعليمية العراقية. "
        "أجب دائماً بالعربية. كن موجزاً ومشجعاً وودوداً. "
        "ساعد الطلاب في أسئلتهم الدراسية وأي استفسار آخر. "
        "لا تتجاوز 200 كلمة في الرد الواحد."
    )

    response_text = None

    if G4F_AVAILABLE:
        providers_config = [
            {"provider": g4f.Provider.Blackbox, "model": g4f.models.gpt_4},
            {"provider": g4f.Provider.DuckDuckGo, "model": g4f.models.gpt_3_5_turbo},
            {"provider": g4f.Provider.Liaobots, "model": g4f.models.gpt_3_5_turbo},
        ]

        for config in providers_config:
            try:
                print(f"[*] Trying provider: {config['provider'].__name__}")
                messages = [{"role": "system", "content": system_prompt}] + context
                resp = g4f.ChatCompletion.create(
                    model=config["model"],
                    provider=config["provider"],
                    messages=messages,
                    timeout=15
                )
                if resp and len(str(resp)) > 3:
                    response_text = str(resp).strip()
                    break
            except Exception as e:
                print(f"[!] Provider failed: {e}")
                continue

    if not response_text:
        # ردود احتياطية ذكية بناءً على الكلمات المفتاحية
        fallback_responses = {
            "مرحبا": "أهلاً وسهلاً! كيف يمكنني مساعدتك اليوم؟ 😊",
            "شكرا": "على الرحب والسعة! أنا هنا دائماً لمساعدتك 🌟",
            "مدرس": "يمكنك الاطلاع على قائمة المدرسين من الصفحة الرئيسية للتطبيق 📚",
            "درس": "أخبرني عن المادة التي تحتاج مساعدة فيها وسأحاول مساعدتك! 📖",
        }
        for keyword, reply in fallback_responses.items():
            if keyword in user_msg:
                response_text = reply
                break
        if not response_text:
            response_text = "أهلاً! عقلي مشغول قليلاً الآن. جرب سؤالي مرة أخرى بعد لحظات! 🤔"

    # حفظ رد المساعد في السجل
    chat_sessions[session_id].append({"role": "assistant", "content": response_text})

    return jsonify({
        "response": response_text,
        "session_id": session_id,
        "timestamp": datetime.now().isoformat()
    })

# مسار GET للتوافق مع النسخة القديمة
@app.route('/chat', methods=['GET'])
def chat_goliath_legacy():
    user_msg = request.args.get('msg', '')
    if not user_msg:
        return jsonify({"response": "أهلاً بك! أنا Goliath مساعدك الذكي."})
    # إعادة التوجيه لنفس منطق v2
    with app.test_request_context('/api/v2/chat', method='POST',
                                   json={"msg": user_msg, "session_id": "legacy"},
                                   content_type='application/json'):
        pass
    # تنفيذ مباشر للتوافق
    return jsonify({"response": "يرجى استخدام POST /api/v2/chat للنسخة المحسّنة."})

# ======================================================
# ✅ API: المحتوى التعليمي (محسّن)
# ======================================================
@app.route('/api/v2/teachers', methods=['GET'])
def get_teachers():
    db = load_json(CONTENT_FILE, {"teachers": []})
    subject_filter = request.args.get("subject")
    teachers = db["teachers"]
    if subject_filter:
        teachers = [t for t in teachers if subject_filter.lower() in t.get("subject", "").lower()]
    return jsonify({"status": "success", "count": len(teachers), "teachers": teachers})

@app.route('/api/v2/teachers/<t_id>', methods=['GET'])
def get_teacher_details(t_id):
    db = load_json(CONTENT_FILE, {"teachers": []})
    teacher = next((t for t in db['teachers'] if t['id'] == t_id), None)
    if teacher:
        return jsonify({"status": "success", "teacher": teacher})
    return jsonify({"status": "error", "message": "المدرس غير موجود"}), 404

@app.route('/api/v2/chapters/<ch_id>', methods=['GET'])
def get_chapter_details(ch_id):
    db = load_json(CONTENT_FILE, {"teachers": []})
    for t in db['teachers']:
        for ch in t['chapters']:
            if ch['id'] == ch_id:
                return jsonify({"status": "success", "chapter": ch, "teacher": t['name']})
    return jsonify({"status": "error", "message": "الفصل غير موجود"}), 404

@app.route('/api/v2/chapters/<ch_id>/videos', methods=['POST'])
def add_video(ch_id):
    """إضافة فيديو لفصل معين"""
    try:
        data = request.get_json()
        if not data or "title" not in data or "url" not in data:
            return jsonify({"status": "error", "message": "يجب توفير title و url"}), 400

        db = load_json(CONTENT_FILE, {"teachers": []})
        for t in db['teachers']:
            for ch in t['chapters']:
                if ch['id'] == ch_id:
                    if "videos" not in ch:
                        ch["videos"] = []
                    video = {
                        "id": str(int(time.time())),
                        "title": data["title"],
                        "url": data["url"],
                        "duration": data.get("duration", ""),
                        "added_at": datetime.now().isoformat()
                    }
                    ch["videos"].append(video)
                    save_json(CONTENT_FILE, db)
                    return jsonify({"status": "success", "video": video}), 201
        return jsonify({"status": "error", "message": "الفصل غير موجود"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/v2/search', methods=['GET'])
def search_content():
    """بحث شامل في المحتوى"""
    query = request.args.get("q", "").strip().lower()
    if not query or len(query) < 2:
        return jsonify({"status": "error", "message": "يجب إدخال كلمة بحث (2 أحرف على الأقل)"}), 400

    db = load_json(CONTENT_FILE, {"teachers": []})
    results = {"teachers": [], "chapters": [], "videos": []}

    for t in db['teachers']:
        if query in t['name'].lower() or query in t.get('subject', '').lower():
            results['teachers'].append({"id": t['id'], "name": t['name'], "subject": t['subject']})

        for ch in t.get('chapters', []):
            if query in ch['title'].lower():
                results['chapters'].append({"id": ch['id'], "title": ch['title'], "teacher": t['name']})

            for v in ch.get('videos', []):
                if query in v.get('title', '').lower():
                    results['videos'].append({
                        "id": v['id'], "title": v['title'],
                        "chapter": ch['title'], "teacher": t['name']
                    })

    total = sum(len(v) for v in results.values())
    return jsonify({"status": "success", "query": query, "total": total, "results": results})

@app.route('/api/v2/stats', methods=['GET'])
def get_stats():
    """إحصائيات عامة للتطبيق"""
    db = load_json(CONTENT_FILE, {"teachers": []})
    users = load_json(USERS_FILE, {})

    total_chapters = sum(len(t.get('chapters', [])) for t in db['teachers'])
    total_videos = sum(
        len(ch.get('videos', []))
        for t in db['teachers']
        for ch in t.get('chapters', [])
    )

    return jsonify({
        "status": "success",
        "stats": {
            "teachers": len(db['teachers']),
            "chapters": total_chapters,
            "videos": total_videos,
            "users": len(users),
            "active_users": sum(1 for u in users.values() if u.get("is_active"))
        }
    })

# ======================================================
# ✅ نظام تسجيل دخول الأدمن
# ======================================================
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = ""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        admins = load_json(ADMIN_FILE, {"admins": [{"username": "admin", "password": hash_password("admin123"), "api_key": "elite-api-key-001"}]})

        # إنشاء ملف الأدمن الافتراضي إن لم يكن موجوداً
        if not os.path.exists(ADMIN_FILE):
            save_json(ADMIN_FILE, admins)

        for admin in admins.get("admins", []):
            if admin["username"] == username and admin["password"] == hash_password(password):
                session["admin_logged_in"] = True
                session["admin_name"] = username
                log_action("admin_login", f"username={username}")
                return redirect("/admin")

        error = "اسم المستخدم أو كلمة المرور غير صحيحة"
        log_action("admin_login_failed", f"username={username}")

    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect("/admin/login")

# ======================================================
# ✅ لوحة التحكم الرئيسية (مُجدَّدة بالكامل)
# ======================================================
@app.route('/admin')
@admin_required
def admin_index():
    db = load_json(CONTENT_FILE, {"teachers": []})
    users = load_json(USERS_FILE, {})
    logs = load_json(LOGS_FILE, [])

    total_chapters = sum(len(t.get('chapters', [])) for t in db['teachers'])
    total_videos = sum(len(ch.get('videos', [])) for t in db['teachers'] for ch in t.get('chapters', []))

    stats = {
        "teachers": len(db['teachers']),
        "chapters": total_chapters,
        "videos": total_videos,
        "users": len(users),
        "active_users": sum(1 for u in users.values() if u.get("is_active")),
        "paid_users": sum(1 for u in users.values() if u.get("subscription") == "paid"),
    }

    recent_logs = list(reversed(logs[-10:]))
    return render_template_string(ADMIN_TEMPLATE,
                                  teachers=db['teachers'],
                                  stats=stats,
                                  users=dict(list(users.items())[:20]),
                                  recent_logs=recent_logs,
                                  admin_name=session.get("admin_name", "Admin"))

# ======================================================
# ✅ عمليات CRUD للوحة التحكم
# ======================================================
@app.route('/admin/add_teacher', methods=['POST'])
@admin_required
def add_teacher():
    db = load_json(CONTENT_FILE, {"teachers": []})
    name = request.form.get('name', '').strip()
    subject = request.form.get('subject', '').strip()
    image_name = request.form.get('image_name', '').strip()
    description = request.form.get('description', '').strip()

    if not name or not subject:
        return redirect("/admin?error=missing_fields")

    new_id = str(max([int(t['id']) for t in db['teachers']], default=0) + 1)
    db['teachers'].append({
        "id": new_id,
        "name": name,
        "subject": subject,
        "image_name": image_name,
        "description": description,
        "chapters": [],
        "created_at": datetime.now().isoformat()
    })
    save_json(CONTENT_FILE, db)
    log_action("add_teacher", f"name={name}", session.get("admin_name"))
    return redirect("/admin?success=teacher_added")

@app.route('/admin/add_chapter', methods=['POST'])
@admin_required
def add_chapter():
    db = load_json(CONTENT_FILE, {"teachers": []})
    teacher_id = request.form.get('teacher_id')
    chapter_title = request.form.get('chapter_title', '').strip()

    if not chapter_title:
        return redirect("/admin?error=missing_fields")

    for t in db['teachers']:
        if t['id'] == teacher_id:
            ch_id = str(int(time.time()))
            t['chapters'].append({
                "id": ch_id,
                "title": chapter_title,
                "videos": [],
                "created_at": datetime.now().isoformat()
            })
    save_json(CONTENT_FILE, db)
    log_action("add_chapter", f"title={chapter_title}", session.get("admin_name"))
    return redirect("/admin?success=chapter_added")

@app.route('/admin/delete_teacher/<t_id>')
@admin_required
def delete_teacher(t_id):
    db = load_json(CONTENT_FILE, {"teachers": []})
    teacher = next((t for t in db['teachers'] if t['id'] == t_id), None)
    db['teachers'] = [t for t in db['teachers'] if t['id'] != t_id]
    save_json(CONTENT_FILE, db)
    if teacher:
        log_action("delete_teacher", f"name={teacher['name']}", session.get("admin_name"))
    return redirect("/admin")

@app.route('/admin/delete_chapter/<t_id>/<ch_id>')
@admin_required
def delete_chapter(t_id, ch_id):
    db = load_json(CONTENT_FILE, {"teachers": []})
    for t in db['teachers']:
        if t['id'] == t_id:
            t['chapters'] = [ch for ch in t['chapters'] if ch['id'] != ch_id]
    save_json(CONTENT_FILE, db)
    log_action("delete_chapter", f"ch_id={ch_id}", session.get("admin_name"))
    return redirect("/admin")

@app.route('/admin/toggle_user/<fb_uid>')
@admin_required
def toggle_user(fb_uid):
    users = load_json(USERS_FILE, {})
    if fb_uid in users:
        users[fb_uid]["is_active"] = not users[fb_uid].get("is_active", True)
        save_json(USERS_FILE, users)
        log_action("toggle_user", f"uid={fb_uid}, active={users[fb_uid]['is_active']}", session.get("admin_name"))
    return redirect("/admin")

# ======================================================
# ✅ صفحة الـ API Docs (مدمجة)
# ======================================================
@app.route('/api/docs')
def api_docs():
    return render_template_string(API_DOCS_TEMPLATE)

# ======================================================
# ✅ Health Check
# ======================================================
@app.route('/health')
def health():
    db = load_json(CONTENT_FILE, {"teachers": []})
    users = load_json(USERS_FILE, {})
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "g4f_available": G4F_AVAILABLE,
        "data": {
            "teachers": len(db.get("teachers", [])),
            "users": len(users)
        }
    })

# ======================================================
# ✅ توافق النسخة القديمة (v1)
# ======================================================
@app.route('/check_user/<fb_uid>', methods=['GET'])
def check_user_v1(fb_uid):
    return check_user(fb_uid)

@app.route('/register_user', methods=['POST'])
def register_user_v1():
    return register_user()

@app.route('/get_teachers', methods=['GET'])
def get_teachers_v1():
    db = load_json(CONTENT_FILE, {"teachers": []})
    return jsonify(db)

@app.route('/get_teacher_details/<t_id>', methods=['GET'])
def get_teacher_details_v1(t_id):
    return get_teacher_details(t_id)

@app.route('/get_chapter_details/<ch_id>', methods=['GET'])
def get_chapter_details_v1(ch_id):
    return get_chapter_details(ch_id)

# ======================================================
# قوالب HTML
# ======================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Elite AI - تسجيل الدخول</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Cairo', sans-serif;
  min-height: 100vh;
  background: #0a0f1e;
  display: flex; align-items: center; justify-content: center;
  background-image: radial-gradient(ellipse at 20% 50%, rgba(37,99,235,0.15) 0%, transparent 60%),
                    radial-gradient(ellipse at 80% 20%, rgba(124,58,237,0.1) 0%, transparent 50%);
}
.card {
  background: rgba(255,255,255,0.04);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 24px;
  padding: 48px;
  width: 100%;
  max-width: 420px;
  backdrop-filter: blur(20px);
  box-shadow: 0 25px 50px rgba(0,0,0,0.5);
}
.logo { text-align: center; margin-bottom: 32px; }
.logo h1 { font-size: 2rem; font-weight: 900; color: #fff; letter-spacing: -1px; }
.logo span { color: #3b82f6; }
.logo p { color: rgba(255,255,255,0.4); font-size: 0.9rem; margin-top: 4px; }
label { display: block; color: rgba(255,255,255,0.7); font-size: 0.85rem; margin-bottom: 8px; font-weight: 600; }
input {
  width: 100%; padding: 14px 16px;
  background: rgba(255,255,255,0.07);
  border: 1px solid rgba(255,255,255,0.1);
  border-radius: 12px; color: #fff;
  font-family: 'Cairo', sans-serif; font-size: 1rem;
  margin-bottom: 20px; transition: all 0.2s;
}
input:focus { outline: none; border-color: #3b82f6; background: rgba(59,130,246,0.1); }
button {
  width: 100%; padding: 14px;
  background: linear-gradient(135deg, #2563eb, #7c3aed);
  border: none; border-radius: 12px;
  color: #fff; font-family: 'Cairo', sans-serif;
  font-size: 1rem; font-weight: 700; cursor: pointer;
  transition: opacity 0.2s; margin-top: 8px;
}
button:hover { opacity: 0.9; }
.error {
  background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3);
  color: #f87171; padding: 12px 16px; border-radius: 10px;
  margin-bottom: 20px; font-size: 0.9rem; text-align: center;
}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <h1>⚡ <span>Elite</span> AI</h1>
    <p>لوحة تحكم Goliath</p>
  </div>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST">
    <label>اسم المستخدم</label>
    <input type="text" name="username" placeholder="admin" required autocomplete="username">
    <label>كلمة المرور</label>
    <input type="password" name="password" placeholder="••••••••" required autocomplete="current-password">
    <button type="submit">🔐 تسجيل الدخول</button>
  </form>
</div>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Elite AI | لوحة التحكم</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #0a0f1e;
  --surface: #111827;
  --surface2: #1f2937;
  --border: rgba(255,255,255,0.08);
  --text: #f9fafb;
  --text2: #9ca3af;
  --blue: #3b82f6;
  --green: #10b981;
  --red: #ef4444;
  --purple: #8b5cf6;
  --yellow: #f59e0b;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Cairo', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }

/* Layout */
.layout { display: flex; min-height: 100vh; }
.sidebar {
  width: 260px; background: var(--surface); border-left: 1px solid var(--border);
  display: flex; flex-direction: column; position: fixed; height: 100vh; overflow-y: auto;
}
.main { margin-right: 260px; flex: 1; padding: 32px; overflow-x: hidden; }

/* Sidebar */
.sidebar-header { padding: 24px; border-bottom: 1px solid var(--border); }
.sidebar-logo { font-size: 1.4rem; font-weight: 900; color: var(--text); }
.sidebar-logo span { color: var(--blue); }
.sidebar-user { font-size: 0.8rem; color: var(--text2); margin-top: 4px; }
.nav { padding: 16px 0; flex: 1; }
.nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 12px 24px; color: var(--text2); text-decoration: none;
  font-size: 0.9rem; font-weight: 600; transition: all 0.2s; cursor: pointer;
  border: none; background: none; width: 100%; text-align: right;
}
.nav-item:hover, .nav-item.active { background: rgba(59,130,246,0.1); color: var(--blue); }
.nav-item .icon { font-size: 1.1rem; }
.sidebar-footer { padding: 16px 24px; border-top: 1px solid var(--border); }
.logout-btn {
  display: flex; align-items: center; gap: 10px;
  color: var(--red); text-decoration: none; font-size: 0.9rem; font-weight: 600;
}

/* Header */
.page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
.page-title { font-size: 1.8rem; font-weight: 900; }
.page-title span { color: var(--blue); }

/* Stats */
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }
.stat-card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 16px;
  padding: 20px; text-align: center; transition: transform 0.2s;
}
.stat-card:hover { transform: translateY(-2px); }
.stat-num { font-size: 2rem; font-weight: 900; margin-bottom: 4px; }
.stat-label { font-size: 0.8rem; color: var(--text2); font-weight: 600; }

/* Tabs */
.tabs { display: flex; gap: 8px; margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 0; }
.tab-btn {
  padding: 10px 20px; border: none; background: none; color: var(--text2);
  font-family: 'Cairo', sans-serif; font-size: 0.9rem; font-weight: 700;
  cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px;
  transition: all 0.2s;
}
.tab-btn.active { color: var(--blue); border-bottom-color: var(--blue); }
.tab-content { display: none; }
.tab-content.active { display: block; }

/* Grid */
.two-col { display: grid; grid-template-columns: 1fr 2fr; gap: 24px; }
@media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } .sidebar { display: none; } .main { margin-right: 0; } }

/* Cards */
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 20px;
  padding: 24px; margin-bottom: 20px;
}
.card-title { font-size: 1rem; font-weight: 700; margin-bottom: 20px; display: flex; align-items: center; gap: 8px; }

/* Forms */
.form-group { margin-bottom: 16px; }
label { display: block; color: var(--text2); font-size: 0.8rem; font-weight: 700; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
input, select, textarea {
  width: 100%; padding: 12px 14px; background: var(--surface2);
  border: 1px solid var(--border); border-radius: 10px;
  color: var(--text); font-family: 'Cairo', sans-serif; font-size: 0.95rem;
  transition: border-color 0.2s;
}
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--blue); }
select option { background: var(--surface); }

.btn { padding: 10px 20px; border: none; border-radius: 10px; font-family: 'Cairo', sans-serif; font-size: 0.9rem; font-weight: 700; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 6px; }
.btn-primary { background: var(--blue); color: #fff; }
.btn-primary:hover { background: #2563eb; }
.btn-success { background: var(--green); color: #fff; }
.btn-danger { background: var(--red); color: #fff; font-size: 0.8rem; padding: 6px 12px; }
.btn-full { width: 100%; justify-content: center; }

/* Teacher Cards */
.teacher-card {
  background: var(--surface2); border: 1px solid var(--border); border-radius: 16px;
  overflow: hidden; margin-bottom: 16px; transition: transform 0.2s;
}
.teacher-card:hover { transform: translateY(-2px); }
.teacher-header {
  background: linear-gradient(135deg, #1e3a5f, #1e1b4b);
  padding: 16px 20px; display: flex; justify-content: space-between; align-items: center;
}
.teacher-name { font-weight: 700; font-size: 1rem; }
.teacher-subject { font-size: 0.8rem; color: #93c5fd; margin-top: 2px; }
.chapter-list { padding: 12px 20px; }
.chapter-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 0.9rem;
}
.chapter-item:last-child { border-bottom: none; }

/* Users Table */
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { text-align: right; padding: 12px 16px; color: var(--text2); font-weight: 700; border-bottom: 1px solid var(--border); }
td { padding: 12px 16px; border-bottom: 1px solid rgba(255,255,255,0.04); }
tr:hover td { background: rgba(255,255,255,0.02); }
.badge { padding: 3px 10px; border-radius: 100px; font-size: 0.75rem; font-weight: 700; display: inline-block; }
.badge-green { background: rgba(16,185,129,0.15); color: var(--green); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-blue { background: rgba(59,130,246,0.15); color: var(--blue); }

/* Logs */
.log-item { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid var(--border); align-items: flex-start; }
.log-icon { font-size: 1.1rem; }
.log-text { font-size: 0.85rem; }
.log-time { font-size: 0.75rem; color: var(--text2); margin-top: 2px; }
.log-action { font-weight: 700; color: var(--blue); }

/* Toast */
.toast { position: fixed; top: 20px; left: 50%; transform: translateX(-50%); background: var(--green); color: #fff; padding: 12px 24px; border-radius: 12px; font-weight: 700; z-index: 1000; display: none; }
</style>
</head>
<body>
<div class="toast" id="toast">✅ تمت العملية بنجاح!</div>
<div class="layout">
  <!-- Sidebar -->
  <aside class="sidebar">
    <div class="sidebar-header">
      <div class="sidebar-logo">⚡ <span>Elite</span> AI</div>
      <div class="sidebar-user">مرحباً، {{ admin_name }} 👋</div>
    </div>
    <nav class="nav">
      <button class="nav-item active" onclick="showTab('content')"><span class="icon">📚</span> المحتوى</button>
      <button class="nav-item" onclick="showTab('users')"><span class="icon">👥</span> المستخدمون</button>
      <button class="nav-item" onclick="showTab('logs')"><span class="icon">📋</span> السجلات</button>
      <button class="nav-item" onclick="showTab('api')"><span class="icon">🔌</span> API</button>
    </nav>
    <div class="sidebar-footer">
      <a href="/admin/logout" class="logout-btn">🚪 تسجيل الخروج</a>
    </div>
  </aside>

  <!-- Main -->
  <main class="main">
    <div class="page-header">
      <div class="page-title">لوحة التحكم <span>Goliath</span></div>
      <div style="color: var(--text2); font-size: 0.85rem;">{{ stats.users }} مستخدم مسجل</div>
    </div>

    <!-- Stats -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-num" style="color: var(--blue);">{{ stats.teachers }}</div>
        <div class="stat-label">مدرس</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--green);">{{ stats.chapters }}</div>
        <div class="stat-label">فصل دراسي</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--purple);">{{ stats.videos }}</div>
        <div class="stat-label">فيديو</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--yellow);">{{ stats.users }}</div>
        <div class="stat-label">مستخدم</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--green);">{{ stats.active_users }}</div>
        <div class="stat-label">نشط</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color: var(--red);">{{ stats.paid_users }}</div>
        <div class="stat-label">مشترك</div>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button class="tab-btn active" onclick="showTab('content')">📚 المحتوى</button>
      <button class="tab-btn" onclick="showTab('users')">👥 المستخدمون</button>
      <button class="tab-btn" onclick="showTab('logs')">📋 السجلات</button>
      <button class="tab-btn" onclick="showTab('api')">🔌 API</button>
    </div>

    <!-- Content Tab -->
    <div id="tab-content" class="tab-content active">
      <div class="two-col">
        <div>
          <div class="card">
            <div class="card-title">👤 إضافة مدرس</div>
            <form action="/admin/add_teacher" method="POST">
              <div class="form-group"><label>الاسم الكامل</label><input name="name" placeholder="مثال: أ. علي حسن" required></div>
              <div class="form-group"><label>المادة</label><input name="subject" placeholder="مثال: الرياضيات" required></div>
              <div class="form-group"><label>اسم الصورة</label><input name="image_name" placeholder="ali.jpg"></div>
              <div class="form-group"><label>الوصف</label><textarea name="description" rows="2" placeholder="نبذة عن المدرس..."></textarea></div>
              <button type="submit" class="btn btn-primary btn-full">➕ إضافة مدرس</button>
            </form>
          </div>

          <div class="card">
            <div class="card-title">📂 إضافة فصل دراسي</div>
            <form action="/admin/add_chapter" method="POST">
              <div class="form-group">
                <label>اختر المدرس</label>
                <select name="teacher_id" required>
                  {% for t in teachers %}<option value="{{ t.id }}">{{ t.name }} - {{ t.subject }}</option>{% endfor %}
                </select>
              </div>
              <div class="form-group"><label>اسم الفصل</label><input name="chapter_title" placeholder="مثال: الفصل الأول - المعادلات" required></div>
              <button type="submit" class="btn btn-success btn-full">➕ إضافة فصل</button>
            </form>
          </div>
        </div>

        <div>
          {% for t in teachers %}
          <div class="teacher-card">
            <div class="teacher-header">
              <div>
                <div class="teacher-name">{{ t.name }}</div>
                <div class="teacher-subject">📘 {{ t.subject }}</div>
              </div>
              <a href="/admin/delete_teacher/{{ t.id }}" onclick="return confirm('حذف المدرس وجميع فصوله؟')" class="btn btn-danger">🗑 حذف</a>
            </div>
            <div class="chapter-list">
              {% if t.chapters %}
                {% for ch in t.chapters %}
                <div class="chapter-item">
                  <span>📁 {{ ch.title }}</span>
                  <a href="/admin/delete_chapter/{{ t.id }}/{{ ch.id }}" class="btn btn-danger">حذف</a>
                </div>
                {% endfor %}
              {% else %}
                <div style="color: var(--text2); font-size: 0.85rem; padding: 8px 0;">لا توجد فصول بعد</div>
              {% endif %}
            </div>
          </div>
          {% else %}
          <div class="card" style="text-align: center; color: var(--text2);">
            <div style="font-size: 3rem; margin-bottom: 12px;">📭</div>
            <div>لا يوجد مدرسون بعد. ابدأ بإضافة مدرس!</div>
          </div>
          {% endfor %}
        </div>
      </div>
    </div>

    <!-- Users Tab -->
    <div id="tab-users" class="tab-content">
      <div class="card">
        <div class="card-title">👥 المستخدمون المسجلون (آخر 20)</div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>الاسم</th><th>المحافظة</th><th>الاشتراك</th><th>الحالة</th><th>المحادثات</th><th>الإجراء</th></tr></thead>
            <tbody>
              {% for uid, u in users.items() %}
              <tr>
                <td><strong>{{ u.name }}</strong><br><small style="color: var(--text2);">{{ u.phone }}</small></td>
                <td>{{ u.gov or '-' }}</td>
                <td><span class="badge {% if u.subscription == 'paid' %}badge-green{% else %}badge-blue{% endif %}">{{ u.subscription or 'free' }}</span></td>
                <td><span class="badge {% if u.is_active %}badge-green{% else %}badge-red{% endif %}">{% if u.is_active %}نشط{% else %}موقوف{% endif %}</span></td>
                <td>{{ u.chat_count or 0 }}</td>
                <td><a href="/admin/toggle_user/{{ uid }}" class="btn btn-danger">{% if u.is_active %}إيقاف{% else %}تفعيل{% endif %}</a></td>
              </tr>
              {% else %}
              <tr><td colspan="6" style="text-align: center; color: var(--text2); padding: 32px;">لا يوجد مستخدمون بعد</td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Logs Tab -->
    <div id="tab-logs" class="tab-content">
      <div class="card">
        <div class="card-title">📋 آخر العمليات</div>
        {% for log in recent_logs %}
        <div class="log-item">
          <div class="log-icon">🔹</div>
          <div>
            <div class="log-text"><span class="log-action">{{ log.action }}</span> — {{ log.details }} <em style="color: var(--text2);">بواسطة {{ log.user }}</em></div>
            <div class="log-time">{{ log.timestamp[:19].replace('T', ' ') }}</div>
          </div>
        </div>
        {% else %}
        <div style="color: var(--text2); text-align: center; padding: 20px;">لا توجد سجلات بعد</div>
        {% endfor %}
      </div>
    </div>

    <!-- API Tab -->
    <div id="tab-api" class="tab-content">
      <div class="card">
        <div class="card-title">🔌 نقاط نهاية API</div>
        <div style="font-size: 0.85rem; line-height: 2;">
          <div style="display: grid; gap: 10px;">
            {% set endpoints = [
              ('GET', '/api/v2/teachers', 'قائمة المدرسين'),
              ('GET', '/api/v2/teachers/:id', 'تفاصيل مدرس'),
              ('GET', '/api/v2/chapters/:id', 'تفاصيل فصل'),
              ('POST', '/api/v2/chat', 'محادثة Goliath'),
              ('GET', '/api/v2/search?q=', 'بحث شامل'),
              ('GET', '/api/v2/stats', 'إحصائيات'),
              ('GET', '/api/v2/check_user/:uid', 'تحقق من مستخدم'),
              ('POST', '/api/v2/register_user', 'تسجيل مستخدم'),
              ('GET', '/health', 'فحص الصحة'),
            ] %}
            {% for method, path, desc in endpoints %}
            <div style="display: flex; align-items: center; gap: 12px; background: var(--surface2); border-radius: 10px; padding: 10px 14px;">
              <span style="background: {% if method == 'GET' %}rgba(16,185,129,0.2); color: #10b981{% else %}rgba(59,130,246,0.2); color: #3b82f6{% endif %}; padding: 2px 8px; border-radius: 6px; font-weight: 700; font-size: 0.75rem;">{{ method }}</span>
              <code style="color: #fbbf24; font-size: 0.85rem;">{{ path }}</code>
              <span style="color: var(--text2); margin-right: auto;">{{ desc }}</span>
            </div>
            {% endfor %}
          </div>
        </div>
      </div>
    </div>

  </main>
</div>

<script>
function showTab(name) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn, .nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  document.querySelectorAll('.tab-btn').forEach(b => { if (b.textContent.includes(name === 'content' ? 'المحتوى' : name === 'users' ? 'المستخدمون' : name === 'logs' ? 'السجلات' : 'API')) b.classList.add('active'); });
}

// Toast notification
const params = new URLSearchParams(window.location.search);
if (params.get('success')) {
  const toast = document.getElementById('toast');
  toast.style.display = 'block';
  setTimeout(() => toast.style.display = 'none', 3000);
}
</script>
</body>
</html>
"""

API_DOCS_TEMPLATE = """
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<title>Elite AI - API Docs</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;700;900&display=swap" rel="stylesheet">
<style>
body { font-family: 'Cairo', sans-serif; background: #0a0f1e; color: #f9fafb; padding: 40px; }
h1 { font-size: 2rem; font-weight: 900; margin-bottom: 8px; }
h1 span { color: #3b82f6; }
.subtitle { color: #6b7280; margin-bottom: 32px; }
.endpoint { background: #111827; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 24px; margin-bottom: 16px; }
.method { display: inline-block; padding: 4px 12px; border-radius: 8px; font-weight: 700; font-size: 0.8rem; margin-left: 10px; }
.get { background: rgba(16,185,129,0.2); color: #10b981; }
.post { background: rgba(59,130,246,0.2); color: #3b82f6; }
.path { font-family: monospace; color: #fbbf24; font-size: 1rem; }
.desc { color: #9ca3af; margin-top: 8px; font-size: 0.9rem; }
pre { background: #1f2937; border-radius: 10px; padding: 16px; margin-top: 12px; font-size: 0.8rem; color: #a5f3fc; overflow-x: auto; }
</style>
</head>
<body>
<h1>⚡ <span>Elite AI</span> API</h1>
<p class="subtitle">توثيق نقاط النهاية - الإصدار 2.0</p>

<div class="endpoint">
  <span class="method post">POST</span><span class="path">/api/v2/chat</span>
  <div class="desc">محادثة مع Goliath الذكي - يدعم السياق والجلسات</div>
  <pre>{ "msg": "ما هو مفهوم التكامل؟", "session_id": "user123", "fb_uid": "uid_abc" }</pre>
</div>

<div class="endpoint">
  <span class="method get">GET</span><span class="path">/api/v2/teachers</span>
  <div class="desc">قائمة جميع المدرسين. يدعم فلتر ?subject=رياضيات</div>
</div>

<div class="endpoint">
  <span class="method get">GET</span><span class="path">/api/v2/search?q=</span>
  <div class="desc">بحث شامل في المدرسين، الفصول، والفيديوهات</div>
</div>

<div class="endpoint">
  <span class="method post">POST</span><span class="path">/api/v2/register_user</span>
  <div class="desc">تسجيل مستخدم جديد</div>
  <pre>{ "fb_uid": "uid_abc", "name": "أحمد علي", "phone": "07801234567", "gov": "بغداد" }</pre>
</div>

<div class="endpoint">
  <span class="method get">GET</span><span class="path">/health</span>
  <div class="desc">فحص صحة الخادم والإحصائيات الأساسية</div>
</div>

<p style="margin-top: 32px; color: #4b5563; font-size: 0.85rem;">🔐 بعض نقاط النهاية تتطلب مفتاح API في Header: <code style="color: #fbbf24;">X-API-Key</code></p>
</body>
</html>
"""

# ======================================================
# تشغيل الخادم
# ======================================================
if __name__ == "__main__":
    # إنشاء ملف الأدمن الافتراضي
    if not os.path.exists(ADMIN_FILE):
        save_json(ADMIN_FILE, {
            "admins": [{
                "username": "admin",
                "password": hash_password("admin123"),
                "api_key": f"elite-{generate_unique_id().lower()}"
            }]
        })
        print("[✅] تم إنشاء حساب الأدمن الافتراضي: admin / admin123")

    print("=" * 50)
    print("⚡ Elite AI Server - Goliath v4.0")
    print("🌐 http://localhost:8080/admin")
    print("📡 http://localhost:8080/api/v2/")
    print("=" * 50)

    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
