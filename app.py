# app.py
# Render / ローカル共通で使える Flask ログインシステム
# - テンプレート: templates/login.html, templates/mypage.html
#   （もし index.html しかない場合は、この下の render_template のファイル名を
#    index.html に変えるか、ファイル名を login.html にリネームしてください）
# - users.json にユーザー情報を保存（将来は DB に移行予定）
# - パスワード: SHA-256 + ユーザーごとのソルト

from __future__ import annotations
import os
import json
import hashlib
import secrets
import string
import tempfile
import threading
from typing import Dict, Any

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

app = Flask(__name__)

# ==== 設定 ==========================================================
# Render では環境変数 SECRET_KEY を設定しておくのが推奨
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATA_FILE = "users.json"
FILE_LOCK = threading.Lock()
RANDOM_PASSWORD_LEN = 12


# ==== ユーティリティ ================================================

def ensure_db() -> None:
    """users.json が無ければ空の {} を作る"""
    if not os.path.exists(DATA_FILE):
        with FILE_LOCK:
            with open(DATA_FILE, "w", encoding="utf-8") as f:
                f.write("{}")


def load_db() -> Dict[str, Any]:
    """ユーザー DB を読み込み"""
    ensure_db()
    with FILE_LOCK:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)


def atomic_save(data: Dict[str, Any]) -> None:
    """テンポラリファイル経由で安全に保存"""
    with FILE_LOCK:
        base_dir = os.path.dirname(os.path.abspath(DATA_FILE)) or "."
        fd, tmp_path = tempfile.mkstemp(
            prefix="users_", suffix=".json", dir=base_dir
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp:
                json.dump(data, tmp, ensure_ascii=False, indent=2)
            os.replace(tmp_path, DATA_FILE)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass


def generate_salt(n_bytes: int = 16) -> str:
    """ソルトを生成（16バイト=32文字のhex）"""
    return secrets.token_hex(n_bytes)


def hash_password(password: str, salt_hex: str) -> str:
    """SHA-256(password + salt) を計算"""
    h = hashlib.sha256()
    h.update(password.encode("utf-8"))
    h.update(bytes.fromhex(salt_hex))
    return h.hexdigest()


def verify_password(password: str, salt_hex: str, hashed_hex: str) -> bool:
    """パスワードが正しいか確認"""
    return hash_password(password, salt_hex) == hashed_hex


def generate_random_password(length: int = RANDOM_PASSWORD_LEN) -> str:
    """英数字から安全なランダムパスワードを生成"""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_username(username: str) -> bool:
    """ユーザー名の簡易チェック（英数字 + _ - のみ）"""
    if not (1 <= len(username) <= 64):
        return False
    allowed = set(string.ascii_letters + string.digits + "_-")
    return all(c in allowed for c in username)


# ==== ルーティング ==================================================

@app.route("/", methods=["GET"])
def show_login():
   # """ログインページ表示"""

    return render_template("login.html")


@app.route("/register", methods=["POST"])
def register():
    
   # 新規登録フォームの処理
    #login.html から username のみ送られてくる想定。
    #パスワードは自動生成してフラッシュメッセージで表示。
    
    username = (request.form.get("username") or "").strip()

    if not validate_username(username):
        flash("ユーザー名が不正です。（英数字と _ - のみ使用可能）", "error")
        return redirect(url_for("show_login"))

    db = load_db()
    if username in db:
        flash("そのユーザー名は既に登録されています。", "error")
        return redirect(url_for("show_login"))

    # パスワード自動生成
    password = generate_random_password()
    salt = generate_salt()
    hashed = hash_password(password, salt)

    db[username] = {"salt": salt, "hash": hashed}
    atomic_save(db)

    flash(f"ユーザー「{username}」を登録しました。初期パスワード：{password}", "success")
    return redirect(url_for("show_login"))


@app.route("/login", methods=["POST"])
def login():
    #ログイン処理
   # username, password をチェックし、成功時は mypage.html を表示。
 
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not validate_username(username):
        flash("ユーザー名が不正です。", "error")
        return redirect(url_for("show_login"))

    db = load_db()
    user = db.get(username)
    if not user:
        flash("ユーザーが存在しません。", "error")
        return redirect(url_for("show_login"))

    if not verify_password(password, user["salt"], user["hash"]):
        flash("ユーザー名またはパスワードが違います。", "error")
        return redirect(url_for("show_login"))

    # ログイン成功
    flash("ログインに成功しました。", "success")
    return render_template("mypage.html", username=username)


@app.route("/reset", methods=["POST"])
def reset_password():
    #パスワード再設定
    # 現在のパスワードを検証
    # 新しいランダムパスワードを発行
    username = (request.form.get("username") or "").strip()
    current_pw = request.form.get("password") or ""

    if not validate_username(username):
        flash("ユーザー名が不正です。", "error")
        return redirect(url_for("show_login"))

    db = load_db()
    user = db.get(username)
    if not user:
        flash("ユーザーが存在しません。", "error")
        return redirect(url_for("show_login"))

    if not verify_password(current_pw, user["salt"], user["hash"]):
        flash("現在のパスワードが正しくありません。", "error")
        return redirect(url_for("show_login"))

    new_pw = generate_random_password()
    new_salt = generate_salt()
    new_hash = hash_password(new_pw, new_salt)
    db[username] = {"salt": new_salt, "hash": new_hash}
    atomic_save(db)

    flash(f"パスワードを再設定しました。新しいパスワード：{new_pw}", "success")
    return redirect(url_for("show_login"))


@app.route("/delete", methods=["POST"])
def delete_user():
    
    #ユーザー削除
    # ユーザー名 + パスワードで本人確認
    # 一致したら users.json から削除

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not validate_username(username):
        flash("ユーザー名が不正です。", "error")
        return redirect(url_for("show_login"))

    db = load_db()
    user = db.get(username)
    if not user:
        flash("ユーザーが存在しません。", "error")
        return redirect(url_for("show_login"))

    if not verify_password(password, user["salt"], user["hash"]):
        flash("パスワードが正しくありません。削除できません。", "error")
        return redirect(url_for("show_login"))

    del db[username]
    atomic_save(db)

    flash(f"ユーザー「{username}」を削除しました。", "success")
    return redirect(url_for("show_login"))


# エントリポイント

if __name__ == "__main__":
    # ローカル実行用（Render では gunicorn app:app を使う）
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
