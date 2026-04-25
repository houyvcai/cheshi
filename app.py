import os
import re
import uuid
import json
import random
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify, session,
    make_response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'quiz-system-secret-key-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f'sqlite:///{os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance", "quiz.db")}'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ── Models ──────────────────────────────────────────────────────────────

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)


class Question(db.Model):
    __tablename__ = 'question'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(500), nullable=False)
    option_b = db.Column(db.String(500), nullable=False)
    option_c = db.Column(db.String(500), nullable=False)
    option_d = db.Column(db.String(500), nullable=False)
    answer = db.Column(db.String(1), nullable=False)
    explanation = db.Column(db.Text, nullable=False)
    order_index = db.Column(db.Integer, nullable=True)


class UserWrong(db.Model):
    __tablename__ = 'user_wrong'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    times_wrong = db.Column(db.Integer, default=1)
    last_wrong_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class UserProgress(db.Model):
    __tablename__ = 'user_progress'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(50), nullable=False)
    question_order = db.Column(db.Text, nullable=False)
    current_index = db.Column(db.Integer, default=0)
    correct_count = db.Column(db.Integer, default=0)
    wrong_count = db.Column(db.Integer, default=0)
    submitted_answers = db.Column(db.Text, default='[]')


# ── Database Migration ──────────────────────────────────────────────────

with app.app_context():
    from sqlalchemy import text as sa_text
    inspector = db.inspect(db.engine)
    existing_cols = [c['name'] for c in inspector.get_columns('question')]
    if 'order_index' not in existing_cols:
        with db.engine.begin() as conn:
            conn.execute(sa_text('ALTER TABLE question ADD COLUMN order_index INTEGER'))
    existing_cols = [c['name'] for c in inspector.get_columns('user_progress')]
    if 'submitted_answers' not in existing_cols:
        with db.engine.begin() as conn:
            conn.execute(sa_text("ALTER TABLE user_progress ADD COLUMN submitted_answers TEXT DEFAULT '[]'"))
    db.create_all()


# ── Auth Decorator ──────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ── Question Parser ─────────────────────────────────────────────────────

def parse_questions(text):
    blocks = re.split(r'={2,}', text)
    questions = []

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        lines = block.split('\n')
        q = {
            'question': '', 'option_a': '', 'option_b': '',
            'option_c': '', 'option_d': '', 'answer': '',
            'explanation': '', 'order_index': None,
        }
        question_text_lines = []
        in_question = False

        for line in lines:
            line = line.strip()
            if not line:
                continue

            m = re.match(r'第\s*(\d+)\s*题[：:](.*)', line)
            if m:
                q['order_index'] = int(m.group(1))
                question_text_lines.append(m.group(2).strip())
                in_question = True
                continue

            m = re.match(r'([ABCD])[.．)）]\s*(.*)', line)
            if m:
                in_question = False
                q[f'option_{m.group(1).lower()}'] = m.group(2).strip()
                continue

            m = re.match(r'答案[：:]\s*([ABCD])', line)
            if m:
                q['answer'] = m.group(1)
                continue

            m = re.match(r'解析[：:](.*)', line)
            if m:
                q['explanation'] = m.group(1).strip()
                continue

            if in_question:
                question_text_lines.append(line)

        q['question'] = ' '.join(question_text_lines).strip()
        if q['question'] and q['answer'] in ('A', 'B', 'C', 'D'):
            questions.append(q)

    return questions


# ── Auth Routes ─────────────────────────────────────────────────────────

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': '用户名或密码不能为空'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': '用户名已存在'}), 400

    user = User(
        username=username,
        password_hash=generate_password_hash(password)
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'success': True, 'message': '注册成功'})


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'error': '用户名或密码错误'}), 400

    session['user_id'] = user.id
    session['username'] = user.username
    return jsonify({'success': True, 'user': {'id': user.id, 'username': user.username}})


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'success': True})


@app.route('/api/auth/status')
def auth_status():
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'user': {'id': session['user_id'], 'username': session['username']}
        })
    return jsonify({'logged_in': False})


# ── Question Bank Routes ────────────────────────────────────────────────

@app.route('/api/questions/count')
@login_required
def question_count():
    return jsonify({'count': Question.query.count()})


@app.route('/api/questions/list')
@login_required
def question_list():
    questions = Question.query.order_by(Question.order_index, Question.id).all()
    return jsonify({'questions': [question_to_dict(q) for q in questions]})


@app.route('/api/questions/edit', methods=['PUT'])
@login_required
def question_edit():
    data = request.json
    qid = data.get('id')
    if not qid:
        return jsonify({'error': '缺少题目ID'}), 400

    question = Question.query.get(qid)
    if not question:
        return jsonify({'error': '题目不存在'}), 404

    question.question = data.get('question', question.question)
    question.option_a = data.get('option_a', question.option_a)
    question.option_b = data.get('option_b', question.option_b)
    question.option_c = data.get('option_c', question.option_c)
    question.option_d = data.get('option_d', question.option_d)
    question.answer = data.get('answer', question.answer)
    question.explanation = data.get('explanation', question.explanation)
    if 'order_index' in data:
        question.order_index = data['order_index']

    db.session.commit()
    return jsonify(question_to_dict(question))


@app.route('/api/questions/delete/<int:qid>', methods=['DELETE'])
@login_required
def question_delete(qid):
    question = Question.query.get(qid)
    if not question:
        return jsonify({'error': '题目不存在'}), 404

    UserWrong.query.filter_by(question_id=qid).delete()
    db.session.delete(question)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/questions/batch-delete', methods=['POST'])
@login_required
def question_batch_delete():
    data = request.json
    ids = data.get('ids', [])
    if not ids:
        return jsonify({'error': '请选择要删除的题目'}), 400

    for qid in ids:
        question = Question.query.get(qid)
        if question:
            UserWrong.query.filter_by(question_id=qid).delete()
            db.session.delete(question)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/questions/import-file', methods=['POST'])
@login_required
def import_file():
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({'error': '请选择文件'}), 400

    content = file.read().decode('utf-8')
    questions = parse_questions(content)

    for q_data in questions:
        q = Question(
            question=q_data['question'],
            option_a=q_data['option_a'],
            option_b=q_data['option_b'],
            option_c=q_data['option_c'],
            option_d=q_data['option_d'],
            answer=q_data['answer'],
            explanation=q_data['explanation'],
            order_index=q_data['order_index'],
        )
        db.session.add(q)
    db.session.commit()

    return jsonify({'success': True, 'imported': len(questions), 'skipped': 0})


@app.route('/api/questions/import-text', methods=['POST'])
@login_required
def import_text():
    text = request.json.get('text', '')
    if not text.strip():
        return jsonify({'error': '请输入题目内容'}), 400

    questions = parse_questions(text)
    for q_data in questions:
        q = Question(
            question=q_data['question'],
            option_a=q_data['option_a'],
            option_b=q_data['option_b'],
            option_c=q_data['option_c'],
            option_d=q_data['option_d'],
            answer=q_data['answer'],
            explanation=q_data['explanation'],
            order_index=q_data['order_index'],
        )
        db.session.add(q)
    db.session.commit()

    return jsonify({'success': True, 'imported': len(questions), 'skipped': 0})


@app.route('/api/questions/export')
@login_required
def export_questions():
    questions = Question.query.order_by(Question.order_index, Question.id).all()
    lines = []
    for q in questions:
        oi = q.order_index if q.order_index is not None else q.id
        lines.append(f'第{oi}题：{q.question}')
        lines.append(f'A. {q.option_a}')
        lines.append(f'B. {q.option_b}')
        lines.append(f'C. {q.option_c}')
        lines.append(f'D. {q.option_d}')
        lines.append(f'答案：{q.answer}')
        lines.append(f'解析：{q.explanation}')
        lines.append('')
        lines.append('===题目分隔线===')
        lines.append('')

    response = make_response('\n'.join(lines))
    response.headers['Content-Disposition'] = 'attachment; filename=quiz_export.md'
    response.headers['Content-Type'] = 'text/markdown; charset=utf-8'
    return response


@app.route('/api/questions/template')
@login_required
def download_template():
    template_path = os.path.join(os.path.dirname(__file__), 'static', 'template.md')
    return make_response(open(template_path, 'rb').read(), {
        'Content-Disposition': 'attachment; filename=question_template.md',
        'Content-Type': 'text/markdown; charset=utf-8',
    })


# ── Quiz Routes ─────────────────────────────────────────────────────────

@app.route('/api/quiz/start', methods=['POST'])
@login_required
def quiz_start():
    questions = Question.query.all()
    if not questions:
        return jsonify({'error': '题库为空，请先导入题目'}), 400

    question_ids = [q.id for q in questions]
    random.shuffle(question_ids)

    session_id = str(uuid.uuid4())
    progress = UserProgress(
        user_id=session['user_id'],
        session_id=session_id,
        question_order=','.join(map(str, question_ids)),
        current_index=0,
        correct_count=0,
        wrong_count=0,
    )
    db.session.add(progress)
    db.session.commit()

    return jsonify({
        'session_id': session_id,
        'total': len(question_ids),
        'current_index': 0,
        'correct_count': 0,
        'wrong_count': 0,
    })


@app.route('/api/quiz/question')
@login_required
def quiz_question():
    session_id = request.args.get('session_id', '')
    if not session_id:
        return jsonify({'error': '缺少session_id'}), 400

    progress = UserProgress.query.filter_by(
        user_id=session['user_id'], session_id=session_id
    ).first_or_404()

    question_ids = [int(x) for x in progress.question_order.split(',') if x]
    total = len(question_ids)

    if progress.current_index >= total:
        return jsonify({
            'completed': True,
            'total': total,
            'correct_count': progress.correct_count,
            'wrong_count': progress.wrong_count,
        })

    question = Question.query.get(question_ids[progress.current_index])
    return jsonify({
        'question': question_to_dict(question),
        'current_index': progress.current_index,
        'total': total,
        'correct_count': progress.correct_count,
        'wrong_count': progress.wrong_count,
        'answered': False,
    })


@app.route('/api/quiz/submit', methods=['POST'])
@login_required
def quiz_submit():
    data = request.json
    session_id = data.get('session_id', '')
    answer = data.get('answer', '').upper()

    if not session_id:
        return jsonify({'error': '缺少session_id'}), 400
    if answer not in ('A', 'B', 'C', 'D'):
        return jsonify({'error': '请选择答案'}), 400

    progress = UserProgress.query.filter_by(
        user_id=session['user_id'], session_id=session_id
    ).first_or_404()

    question_ids = [int(x) for x in progress.question_order.split(',') if x]
    total = len(question_ids)

    if progress.current_index >= total:
        return jsonify({'error': '答题已完成'}), 400

    question = Question.query.get(question_ids[progress.current_index])
    is_correct = answer == question.answer

    if not is_correct:
        existing = UserWrong.query.filter_by(
            user_id=session['user_id'],
            question_id=question.id,
        ).first()
        if existing:
            existing.times_wrong += 1
            existing.last_wrong_time = datetime.now(timezone.utc)
        else:
            db.session.add(UserWrong(
                user_id=session['user_id'],
                question_id=question.id,
                times_wrong=1,
                last_wrong_time=datetime.now(timezone.utc),
            ))

    progress.current_index += 1
    if is_correct:
        progress.correct_count += 1
    else:
        progress.wrong_count += 1

    # Track results for 10-question summary in DB
    answers = json.loads(progress.submitted_answers or '[]')
    answers.append(is_correct)
    progress.submitted_answers = json.dumps(answers)

    db.session.commit()

    # Check if we should show 10-question summary
    is_summary = (progress.current_index > 0 and progress.current_index % 10 == 0)
    result = {
        'correct': is_correct,
        'correct_answer': question.answer,
        'explanation': question.explanation,
        'total': total,
        'current_index': progress.current_index,
        'correct_count': progress.correct_count,
        'wrong_count': progress.wrong_count,
        'is_summary': is_summary,
    }

    if is_summary:
        recent = answers[-10:]
        result['last_10_correct'] = sum(1 for r in recent if r)
        result['last_10_wrong'] = len(recent) - result['last_10_correct']

    return jsonify(result)


@app.route('/api/quiz/progress')
@login_required
def quiz_progress():
    session_id = request.args.get('session_id', '')
    if not session_id:
        return jsonify({'error': '缺少session_id'}), 400

    progress = UserProgress.query.filter_by(
        user_id=session['user_id'], session_id=session_id
    ).first_or_404()

    question_ids = [int(x) for x in progress.question_order.split(',') if x]
    total = len(question_ids)

    return jsonify({
        'current_index': progress.current_index,
        'total': total,
        'correct_count': progress.correct_count,
        'wrong_count': progress.wrong_count,
    })


# ── Wrong Book Routes ───────────────────────────────────────────────────

@app.route('/api/wrong/list')
@login_required
def wrong_list():
    wrongs = UserWrong.query.filter_by(
        user_id=session['user_id']
    ).order_by(UserWrong.last_wrong_time.desc()).all()

    result = []
    for w in wrongs:
        question = Question.query.get(w.question_id)
        if question:
            result.append({
                'wrong_id': w.id,
                'question_id': question.id,
                'order_index': question.order_index,
                'question': question.question,
                'option_a': question.option_a,
                'option_b': question.option_b,
                'option_c': question.option_c,
                'option_d': question.option_d,
                'answer': question.answer,
                'explanation': question.explanation,
                'times_wrong': w.times_wrong,
                'last_wrong_time': w.last_wrong_time.isoformat() if w.last_wrong_time else None,
            })
    return jsonify({'wrong_answers': result})


@app.route('/api/wrong/remove', methods=['POST'])
@login_required
def wrong_remove():
    data = request.json
    question_id = data.get('question_id')
    if not question_id:
        return jsonify({'error': '缺少question_id'}), 400

    UserWrong.query.filter_by(
        user_id=session['user_id'], question_id=question_id
    ).delete()
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/wrong/clear', methods=['POST'])
@login_required
def wrong_clear():
    UserWrong.query.filter_by(user_id=session['user_id']).delete()
    db.session.commit()
    return jsonify({'success': True})


# ── Helpers ─────────────────────────────────────────────────────────────

def question_to_dict(question):
    return {
        'id': question.id,
        'order_index': question.order_index,
        'question': question.question,
        'option_a': question.option_a,
        'option_b': question.option_b,
        'option_c': question.option_c,
        'option_d': question.option_d,
        'answer': question.answer,
        'explanation': question.explanation,
    }


# ── Page Routes ─────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/quiz')
def quiz_page():
    return render_template('index.html')


# ── Run ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, port=5000)
