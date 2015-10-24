#!/usr/bin/env python3
import cherrypy
import sqlalchemy
import crypt
import time
import uuid
from cherrypy.process import plugins
from sqlalchemy import create_engine, func
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

# ==========Config==========
DATABASE_FILE = "tsuru2d.db"
API_PATH = "/apiv1"
SERVER_PORT = 8080
TOKEN_EXPIRATION_TIME_DAYS = 14
# ==========================


class SAEnginePlugin(plugins.SimplePlugin):
    def __init__(self, bus, db_path):
        plugins.SimplePlugin.__init__(self, bus)
        self.sa_engine = None
        self.bus.subscribe("bind", self.bind)
        self.db_path = db_path

    def start(self):
        self.sa_engine = create_engine("sqlite:///" + self.db_path)
        Base.metadata.create_all(self.sa_engine)

    def stop(self):
        if self.sa_engine:
            self.sa_engine.dispose()
            self.sa_engine = None

    def bind(self, session):
        session.configure(bind=self.sa_engine)


class SATool(cherrypy.Tool):
    def __init__(self):
        cherrypy.Tool.__init__(self, "on_start_resource", self.bind_session, priority=20)
        self.session = scoped_session(sessionmaker(autoflush=True, autocommit=False))

    def _setup(self):
        cherrypy.Tool._setup(self)
        cherrypy.request.hooks.attach("on_end_resource", self.commit_transaction, priority=80)

    def bind_session(self):
        cherrypy.engine.publish("bind", self.session)
        cherrypy.request.db = self.session

    def commit_transaction(self):
        cherrypy.request.db = None
        try:
            self.session.commit()
        except:
            self.session.rollback()  
            raise
        finally:
            self.session.remove()


class User(Base):
    __tablename__ = "users"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    email = sqlalchemy.Column(sqlalchemy.Text, unique=True, nullable=False)
    password_hash = sqlalchemy.Column(sqlalchemy.Text, nullable=False)
    password_salt = sqlalchemy.Column(sqlalchemy.Text, nullable=False)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False)
    value = sqlalchemy.Column(sqlalchemy.String(32), unique=True, nullable=False)
    expiration_time = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)


class Game(Base):
    __tablename__ = "games"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    package_name = sqlalchemy.Column(sqlalchemy.Text, nullable=False)


class SaveData(Base):
    __tablename__ = "save_data"
    __table_args__ = (sqlalchemy.UniqueConstraint("user_id", "game_id", "save_index"),)
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False)
    game_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("games.id"), nullable=False)
    save_index = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    save_version = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    save_time = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)
    scene_id = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    frame_id = sqlalchemy.Column(sqlalchemy.String, nullable=False)
    custom_state = sqlalchemy.Column(sqlalchemy.Text, nullable=False)


def generate_auth_token():
    token_value = uuid.uuid4().hex
    expiration_time = int(time.time() * 1000) + TOKEN_EXPIRATION_TIME_DAYS * 24 * 60 * 60 * 1000
    return (token_value, expiration_time)


def validate_auth_token(db_session, token_value):
    if not token_value:
        return (False, "invalid_auth_token")
    auth_token = db_session.query(AuthToken).filter(AuthToken.value == token_value).first()
    if not auth_token:
        return (False, "invalid_auth_token")
    if int(auth_token.expiration_time) < int(time.time() * 1000):
        return (False, "auth_token_expired")
    return (True, auth_token.user_id)


def json_error(msg):
    return {
        "success": False,
        "error": msg
    }


class Server:
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def create_user(self):
        json = cherrypy.request.json
        email = json.get("email")
        if not email:
            return json_error("invalid_email")
        user_check = cherrypy.request.db.query(User).filter(User.email == email).first()
        if user_check:
            return json_error("user_already_exists")
        password = json.get("password")
        if not password:
            return json_error("invalid_password")
        password_salt = crypt.mksalt()
        password_hash =  crypt.crypt(password, password_salt)
        user = User(email=email, password_hash=password_hash, password_salt=password_salt)
        cherrypy.request.db.add(user)
        cherrypy.request.db.flush()
        cherrypy.request.db.refresh(user)
        token_value, expiration_time = generate_auth_token()
        auth_token = AuthToken(user_id=user.id, value=token_value, expiration_time=expiration_time)
        cherrypy.request.db.add(auth_token)
        return {
            "success": True,
            "auth_token": token_value
        }

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def login(self):
        json = cherrypy.request.json
        email = json.get("email")
        password = json.get("password")
        if not email:
            return json_error("user_not_found")
        user = cherrypy.request.db.query(User).filter(User.email == email).first()
        if not user:
            return json_error("user_not_found")
        if not password or user.password_hash != crypt.crypt(password, user.password_salt):
            return json_error("incorrect_password")
        token_value, expiration_time = generate_auth_token()
        auth_token = AuthToken(user_id=user.id, value=token_value, expiration_time=expiration_time)
        cherrypy.request.db.add(auth_token)
        return {
            "success": True,
            "auth_token": token_value
        }

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def create_game(self):
        json = cherrypy.request.json
        game_package = json.get("game_package")
        if not game_package:
            return json_error("invalid_game_package")
        game_check = cherrypy.request.db.query(Game).filter(Game.package_name == game_package).first()
        if game_check:
            return json_error("game_already_exists")
        game = Game(package_name=game_package)
        cherrypy.request.db.add(game)
        return {
            "success": True
        }

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def write_save(self):
        json = cherrypy.request.json
        token_value = json.get("auth_token")
        auth_success, ret = validate_auth_token(cherrypy.request.db, token_value)
        if not auth_success:
            return json_error(ret)
        user_id = ret
        game_package = json.get("game_package")
        game = cherrypy.request.db.query(Game).filter(Game.package_name == game_package).first()
        if not game:
            return json_error("invalid_game_package")
        game_id = game.id
        save_data = SaveData(
            user_id=user_id,
            game_id=game_id,
            save_index=json.get("index"),
            save_version=json.get("version"),
            save_time=json.get("time"),
            scene_id=json.get("scene_id"),
            frame_id=json.get("frame_id"),
            custom_state=json.get("custom_state"))
        cherrypy.request.db.add(save_data)
        cherrypy.request.db.flush()
        cherrypy.request.db.refresh(save_data)
        return {
            "success": True,
            "save_id": save_data.id
        }

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def delete_save(self):
        json = cherrypy.request.json
        token_value = json.get("auth_token")
        auth_success, ret = validate_auth_token(cherrypy.request.db, token_value)
        if not auth_success:
            return json_error(ret)
        user_id = ret
        save_id = json.get("save_id")
        if not save_id:
            return json_error("invalid_save_id")
        delete_count = cherrypy.request.db.query(SaveData)\
            .filter(SaveData.id == save_id, SaveData.user_id == user_id)\
            .delete()
        if delete_count == 0:
            return json_error("delete_failed")
        return {
            "success": True
        }

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def enumerate_saves(self):
        json = cherrypy.request.json
        token_value = json.get("auth_token")
        auth_success, ret = validate_auth_token(cherrypy.request.db, token_value)
        if not auth_success:
            return json_error(ret)
        user_id = ret
        game_package = json.get("game_package")
        if not game_package:
            return json_error("invalid_game_package")
        game = cherrypy.request.db.query(Game).filter(Game.package_name == game_package).first()
        if not game:
            return json_error("invalid_game_package")
        game_id = game.id
        query = cherrypy.request.db.query(SaveData).filter(SaveData.game_id == game_id, SaveData.user_id == user_id)
        saves = [{
            "save_id": s.id,
            "index": s.save_index,
            "version": s.save_version,
            "time": s.save_time,
            "scene_id": s.scene_id,
            "frame_id": s.frame_id,
            "custom_state": s.custom_state
        } for s in query]
        return {
            "success": True,
            "saves": saves
        }


if __name__ == "__main__":
    SAEnginePlugin(cherrypy.engine, DATABASE_FILE).subscribe()
    cherrypy.tools.db = SATool()
    cherrypy.tree.mount(Server(), API_PATH)
    cherrypy.config.update({
        "engine.autoreload.on": False,
        "tools.db.on": True,
        "server.socket_port": SERVER_PORT
    })
    cherrypy.engine.start()
    cherrypy.engine.block()
