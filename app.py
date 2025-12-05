# app.py
# PostgreSQL版 Flask ログインシステム
# - テンプレート: templates/login.html, templates/mypage.html
# - ユーザー情報は PostgreSQL の users テーブルに保存
# - パスワード: SHA-256 + ユーザーごとのソルト

from __future__ import annotations
import os
import hashlib
import secrets
import string
from typing import Optional

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
)

import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# ==================== DB 接続まわり ====================

def get_connection():
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError("環境変数 DATABASE_URL が設定されていません。")
    # Render の Internal Database URL を想定
    conn = psycopg2.connect(dsn, cursor_factory=RealDictCursor)
    return conn


def init_db():
  #  """users テーブルが無ければ作成する"""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL UNIQUE,
                    salt CHAR(32) NOT NULL,
                    password_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
        conn.commit()
    finally:
        conn.close()


def get_user(username: str) -> Optional[dict]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,),
            )
            return cur.fetchone()
    finally:
        conn.close()


def create_user(username: str, salt: str, password_hash: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, salt, password_hash)
                VALUES (%s, %s, %s)
                """,
                (username, salt, password_hash),
            )
        conn.commit()
    finally:
        conn.close()


def update_password(username: str, new_salt: str, new_hash: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET salt = %s, password_hash = %s
                WHERE username = %s
                """,
                (new_salt, new_hash, username),
            )
        conn.commit()
    finally:
        conn.close()


def delete_user_db(username: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
        conn.commit()
    finally:
        conn.close()


# ==================== パスワード関連ユーティリティ ====================

def generate_salt(n_bytes: int = 16) -> str:
   # """ソルトを生成（16バイト=32文字hex）"""
    return secrets.token_hex(n_bytes)


def hash_password(password: str, salt_hex: str) -> str:
   # """SHA-256(password + salt)"""
    h = hashlib.sha256()
    h.update(password.encode("utf-8"))
    h.update(bytes.fromhex(salt_hex))
    return h.hexdigest()


def verify_password(password: str, salt_hex: str, hashed_hex: str) -> bool:
    return hash_password(password, salt_hex) == hashed_hex


def generate_random_password(length: int = 12) -> str:
  #  """英数字ランダムパスワード"""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def validate_username(username: str) -> bool:
 #   """ユーザー名を簡易チェック（英数字 + _ - のみ）"""
    if not (1 <= len(username) <= 64):
        return False
    allowed = set(string.ascii_letters + string.digits + "_-")
    return all(c in allowed for c in username)


# ==================== ルーティング ====================

@app.route("/", methods=["GET"])
def show_login():
   # """ログインページ表示"""

    return render_template("login.html")


@app.route("/register", methods=["POST"])
def register():
   # """新規登録"""
    username = (request.form.get("username") or "").strip()

    if not validate_username(username):
        flash("ユーザー名が不正です。（英数字と _ - のみ）", "error")
        return redirect(url_for("show_login"))

    if get_user(username) is not None:
        flash("そのユーザー名は既に登録されています。", "error")
        return redirect(url_for("show_login"))

    # パスワード自動生成 + ハッシュ化
    password = generate_random_password()
    salt = generate_salt()
    hashed = hash_password(password, salt)

    create_user(username, salt, hashed)

    flash(f"ユーザー「{username}」を登録しました。初期パスワード：{password}", "success")
    return redirect(url_for("show_login"))


@app.route("/login", methods=["POST"])
def login():
    #"""ログイン処理"""
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not validate_username(username):
        flash("ユーザー名が不正です。", "error")
        return redirect(url_for("show_login"))

    user = get_user(username)
    if not user:
        flash("ユーザーが存在しません。", "error")
        return redirect(url_for("show_login"))

    if not verify_password(password, user["salt"], user["password_hash"]):
        flash("ユーザー名またはパスワードが違います。", "error")
        return redirect(url_for("show_login"))

    flash("ログインに成功しました。", "success")
    return render_template("mypage.html", username=username)


@app.route("/reset", methods=["POST"])
def reset_password():
   # """パスワード再設定"""
    username = (request.form.get("username") or "").strip()
    current_pw = request.form.get("password") or ""

    if not validate_username(username):
        flash("ユーザー名が不正です。", "error")
        return redirect(url_for("show_login"))

    user = get_user(username)
    if not user:
        flash("ユーザーが存在しません。", "error")
        return redirect(url_for("show_login"))

    if not verify_password(current_pw, user["salt"], user["password_hash"]):
        flash("現在のパスワードが正しくありません。", "error")
        return redirect(url_for("show_login"))

    new_pw = generate_random_password()
    new_salt = generate_salt()
    new_hash = hash_password(new_pw, new_salt)
    update_password(username, new_salt, new_hash)

    flash(f"パスワードを再設定しました。新しいパスワード：{new_pw}", "success")
    return redirect(url_for("show_login"))


@app.route("/delete", methods=["POST"])
def delete_user():
   # """ユーザー削除"""
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not validate_username(username):
        flash("ユーザー名が不正です。", "error")
        return redirect(url_for("show_login"))

    user = get_user(username)
    if not user:
        flash("ユーザーが存在しません。", "error")
        return redirect(url_for("show_login"))

    if not verify_password(password, user["salt"], user["password_hash"]):
        flash("パスワードが正しくありません。削除できません。", "error")
        return redirect(url_for("show_login"))

    delete_user_db(username)
    flash(f"ユーザー「{username}」を削除しました。", "success")
    return redirect(url_for("show_login"))


# ==================== エントリポイント ====================

# モジュール読み込み時にテーブルを用意しておく
try:
    init_db()
except Exception as e:
    print("DB初期化に失敗しました:", e)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
