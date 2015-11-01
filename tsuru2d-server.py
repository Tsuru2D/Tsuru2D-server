#!/usr/bin/env python3
import json
import os
import time
import uuid

import cherrypy
import passlib.hash
import sqlalchemy
import sqlalchemy.ext.declarative

# ==========Config==========
DATABASE_URI = os.environ["DATABASE_URL"]
SERVER_PORT = int(os.environ["PORT"])
API_PATH = "/apiv1"
TOKEN_EXPIRATION_TIME = 14 * 24 * 60 * 60
# ==========================


class SAEnginePlugin(cherrypy.process.plugins.SimplePlugin):
    def __init__(self, bus, db_uri):
        super().__init__(bus)
        self.sa_engine = None
        self.bus.subscribe("bind", self.bind)
        self.db_uri = db_uri

    def start(self):
        self.sa_engine = sqlalchemy.create_engine(self.db_uri)
        Base.metadata.create_all(self.sa_engine)

    def stop(self):
        if self.sa_engine:
            self.sa_engine.dispose()
            self.sa_engine = None

    def bind(self, session):
        session.configure(bind=self.sa_engine)


class SATool(cherrypy.Tool):
    def __init__(self):
        super().__init__("on_start_resource", self.bind_session, priority=20)
        self.session = sqlalchemy.orm.scoped_session(
            sqlalchemy.orm.sessionmaker(autoflush=True, autocommit=False))

    def _setup(self):
        super()._setup()
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


Base = sqlalchemy.ext.declarative.declarative_base()


class User(Base):
    __tablename__ = "users"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    email = sqlalchemy.Column(sqlalchemy.Text, unique=True, nullable=False)
    password_hash = sqlalchemy.Column(sqlalchemy.Text, nullable=False)


class AuthToken(Base):
    __tablename__ = "auth_tokens"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False)
    token_value = sqlalchemy.Column(sqlalchemy.String(32), unique=True, nullable=False)
    expiration_time = sqlalchemy.Column(sqlalchemy.Integer, nullable=False)


class Game(Base):
    __tablename__ = "games"
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    package_name = sqlalchemy.Column(sqlalchemy.Text, unique=True, nullable=False)


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


class GameSettings(Base):
    __tablename__ = "game_settings"
    __table_args__ = (sqlalchemy.UniqueConstraint("user_id", "game_id"),)
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id"), nullable=False)
    game_id = sqlalchemy.Column(sqlalchemy.Integer, sqlalchemy.ForeignKey("games.id"), nullable=False)
    settings_table = sqlalchemy.Column(sqlalchemy.Text, nullable=False)


def get_user_by_email(db_session, email):
    if not email:
        return None
    return db_session.query(User)\
        .filter(User.email == email)\
        .first()


def get_game_by_package(db_session, package_name):
    if not package_name:
        return None
    return db_session.query(Game)\
        .filter(Game.package_name == package_name)\
        .first()


def get_save_data(db_session, user_id, game_id, save_index):
    return db_session.query(SaveData)\
        .filter(
            SaveData.user_id == user_id, 
            SaveData.game_id == game_id, 
            SaveData.save_index == save_index)\
        .first()


def get_game_settings(db_session, user_id, game_id):
    return db_session.query(GameSettings)\
        .filter(
            GameSettings.user_id == user_id,
            GameSettings.game_id == game_id)\
        .first()


def current_unix_time():
    return int(time.time())


def generate_auth_token(db_session, user_id):
    token_value = uuid.uuid4().hex
    expiration_time = current_unix_time() + TOKEN_EXPIRATION_TIME
    auth_token = AuthToken(
        user_id=user_id,
        token_value=token_value,
        expiration_time=expiration_time)
    db_session.add(auth_token)
    return token_value


def validate_auth_token(db_session, token_value):
    if not token_value:
        return (False, "invalid_auth_token")
    auth_token = db_session.query(AuthToken)\
        .filter(AuthToken.token_value == token_value)\
        .first()
    if not auth_token:
        return (False, "invalid_auth_token")
    if auth_token.expiration_time < current_unix_time():
        return (False, "auth_token_expired")
    return (True, auth_token.user_id)


def get_user_game_ids(db_session, request_json):
    token_value = request_json.get("auth_token")
    auth_success, ret = validate_auth_token(db_session, token_value)
    if not auth_success:
        return (False, ret)
    user_id = ret
    game_package = request_json.get("game_package")
    game = get_game_by_package(db_session, game_package)
    if not game:
        return (False, "invalid_game_package")
    game_id = game.id
    return (True, (user_id, game_id))


def hash_password(password_plaintext):
    return passlib.hash.pbkdf2_sha512.encrypt(password_plaintext)


def verify_password(password_plaintext, password_hash):
    if not password_plaintext:
        return False
    return passlib.hash.pbkdf2_sha512.verify(password_plaintext, password_hash)


def save_data_to_json(save_data):
    return {
        "save_id": save_data.id,
        "index": save_data.save_index,
        "version": save_data.save_version,
        "time": save_data.save_time,
        "scene_id": save_data.scene_id,
        "frame_id": save_data.frame_id,
        "custom_state": json.loads(save_data.custom_state)
    }


def json_to_save_data(request_json, user_id, game_id):
    return SaveData(
        user_id=user_id,
        game_id=game_id,
        save_index=request_json.get("index"),
        save_version=request_json.get("version"),
        save_time=request_json.get("time"),
        scene_id=request_json.get("scene_id"),
        frame_id=request_json.get("frame_id"),
        custom_state=json.dumps(request_json.get("custom_state")))


def update_save_data(request_json, save_data):
    save_data.save_version = request_json.get("version")
    save_data.save_time = request_json.get("time")
    save_data.scene_id = request_json.get("scene_id")
    save_data.frame_id = request_json.get("frame_id")
    save_data.custom_state = json.dumps(request_json.get("custom_state"))


def json_success(data=None):
    if not data:
        data = {}
    data["success"] = True
    return data


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
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        email = request_json.get("email")
        if not email:
            return json_error("invalid_email")
        password = request_json.get("password")
        if not password:
            return json_error("invalid_password")
        password_hash = hash_password(password)
        user = User(email=email, password_hash=password_hash)
        session.add(user)
        try:
            session.flush()
        except sqlalchemy.exc.IntegrityError as e:
            session.rollback()
            return json_error("user_already_exists")
        session.refresh(user)
        token_value = generate_auth_token(session, user.id)
        return json_success({
            "auth_token": token_value
        })

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def login(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        email = request_json.get("email")
        password = request_json.get("password")
        user = get_user_by_email(session, email)
        if not user:
            return json_error("user_not_found")
        if not verify_password(password, user.password_hash):
            return json_error("incorrect_password")
        token_value = generate_auth_token(session, user.id)
        return json_success({
            "auth_token": token_value
        })

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def logout(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        token_value = request_json.get("auth_token")
        if not token_value:
            return json_error("invalid_auth_token")
        delete_count = session.query(AuthToken)\
            .filter(AuthToken.token_value == token_value)\
            .delete()
        if delete_count == 0:
            return json_error("invalid_auth_token")
        return json_success()

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def create_game(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        game_package = request_json.get("game_package")
        if not game_package:
            return json_error("invalid_game_package")
        game = Game(package_name=game_package)
        session.add(game)
        try:
            session.flush()
        except sqlalchemy.exc.IntegrityError as e:
            session.rollback()
            return json_error("game_already_exists")
        return json_success()

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def write_save(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        auth_success, ret = get_user_game_ids(session, request_json)
        if not auth_success:
            return json_error(ret)
        user_id, game_id = ret
        save_index = request_json.get("index")
        overwrite = request_json.get("overwrite", False)
        save_data = get_save_data(session, user_id, game_id, save_index)
        if save_data and not overwrite:
            return json_error("save_data_already_exists")
        if save_data:
            update_save_data(request_json, save_data)
        else:
            save_data = json_to_save_data(request_json, user_id, game_id)
            session.add(save_data)
        session.flush()
        session.refresh(save_data)
        return json_success({
            "save_id": save_data.id
        })

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def delete_save(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        token_value = request_json.get("auth_token")
        auth_success, ret = validate_auth_token(session, token_value)
        if not auth_success:
            return json_error(ret)
        user_id = ret
        save_id = request_json.get("save_id")
        if not save_id:
            return json_error("invalid_save_id")
        delete_count = session.query(SaveData)\
            .filter(SaveData.id == save_id, SaveData.user_id == user_id)\
            .delete()
        if delete_count == 0:
            # TODO: Make this error more clear
            # (permission denied, save doesn't exist, etc)
            return json_error("delete_failed")
        return json_success()

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def enumerate_saves(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        auth_success, ret = get_user_game_ids(session, request_json)
        if not auth_success:
            return json_error(ret)
        user_id, game_id = ret
        from_index = request_json.get("from_index")
        to_index = request_json.get("to_index")
        query = session.query(SaveData)\
            .filter(SaveData.game_id == game_id, SaveData.user_id == user_id)
        if from_index:
            query = query.filter(SaveData.save_index >= from_index)
        if to_index:
            query = query.filter(SaveData.save_index <= to_index)
        saves = [save_data_to_json(save_data) for save_data in query]
        return json_success({
            "saves": saves
        })

    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def read_game_settings(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        auth_success, ret = get_user_game_ids(session, request_json)
        if not auth_success:
            return json_error(ret)
        user_id, game_id = ret
        game_settings = get_game_settings(session, user_id, game_id)
        settings_table = {}
        if game_settings:
            settings_table = json.loads(game_settings.settings_table)
        return json_success({
            "settings": settings_table
        })


    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    @cherrypy.expose
    def write_game_settings(self):
        request_json = cherrypy.request.json
        session = cherrypy.request.db
        auth_success, ret = get_user_game_ids(session, request_json)
        if not auth_success:
            return json_error(ret)
        user_id, game_id = ret
        settings_table = request_json.get("settings")
        if settings_table is None:
            return json_error("invalid_game_settings")
        settings_str = json.dumps(settings_table)
        game_settings = get_game_settings(session, user_id, game_id)
        if not game_settings:
            game_settings = GameSettings(
                user_id=user_id,
                game_id=game_id,
                settings_table=settings_str)
            session.add(game_settings)
        else:
            game_settings.settings_table = settings_str
        return json_success()


if __name__ == "__main__":
    SAEnginePlugin(cherrypy.engine, DATABASE_URI).subscribe()
    cherrypy.tools.db = SATool()
    cherrypy.tree.mount(Server(), API_PATH)
    cherrypy.config.update({
        "engine.autoreload.on": False,
        "tools.db.on": True,
        "server.socket_port": SERVER_PORT
    })
    cherrypy.engine.start()
    cherrypy.engine.block()
