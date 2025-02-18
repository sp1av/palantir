from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import psycopg2
import os
import requests
from sqlalchemy import nullsfirst
import multiprocessing
import threading
import importlib
import json
import pwn
from sqlalchemy.dialects.postgresql import JSONB

from config import Config

config = {}
config["modules"] = {}
scan_result = {}

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)


class Docker(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True)
    docker_id = db.Column(db.String(20)) # docker container id
    scan_id = db.Column(db.Integer, nullable=False) # id of scan
    os = db.Column(db.String(20)) # os in docker
    port = db.Column(db.Integer, nullable=False) # port for this scan
    state = db.Column(db.String(20), nullable=False)
    inspect = db.Column(JSONB) # row for docker inspect output
    vulnerabilities = db.Column(JSONB)


class Scans(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True) #scan id
    uuid = db.Column(db.String(40), nullable=False, unique=True) # uuid.uuid4() - len=38 - for control
    name = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(10), nullable=False) # Recurring/One-time
    mode = db.Column(db.String(20), nullable=False) # offensive/defensive
    date = db.Column(db.String(20), nullable=False) # "2001-70-30 16:13:00"
    state = db.Column(db.String(20), nullable=False) # pending/ongoing/finished
    password = db.Column(db.String(40), nullable=False, unique=True)


class Ports(db.Model):
    __bind_key__ = 'dckesc'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, nullable=False)
    port = db.Column(db.Integer, unique=True, nullable=False)


def control(read_til, server, cmd):
    server.sendline((cmd).encode("utf-8"))
    ans = server.recvuntil(read_til.encode('utf-8')).decode('utf-8')
    ans = ans.replace(cmd, '')
    ans = ans.replace(read_til, '').strip()
    return ans


def parse_modules():
    modules_dir = "modules"
    global config

    def process_config(data):
        global config
        module_name = data.get("module_name")
        data_from_main = data.get("data_from_main")


        config["modules"][module_name] = {
            "name": module_name,
            "data_from_main": data_from_main
        }

    def process_module(module_path):
        config_path = os.path.join(module_path, 'config.json')
        with open(config_path, 'r') as config_file:
            config_data = json.load(config_file)
            process_config(config_data)

    for root, dirs, files in os.walk(modules_dir):
        for dir_name in dirs:
            module_path = os.path.join(root, dir_name)
            if "__pycache__" not in module_path:
                process_module(module_path)


def proceed_target(data, mode, scan_id):
    local_results = {}
    report = requests.Session()
    def worker(target_port, share_result, id, password):
        global scan_result
        result = {}
        conn = pwn.remote("127.0.0.1", target_port)
        conn.recv(17)
        conn.sendline(password.encode("utf-8"))
        conn.recvline()
        conn.sendline(''.encode('utf-8'))
        conn.recvline()
        read_til = (conn.recvuntil(b":/").decode('utf-8') + conn.recv(1).decode('utf-8'))
        conn.recvuntil(read_til.encode('utf-8')).decode('utf-8')
        ans = load_module("basic_checks", read_til, conn)
        data = {"result": str(ans)}
        report.post(f"http://127.0.0.1:2517/api/update/{id}", data=data)

        def clean(procs):
            ret = []
            procs = list(procs.split("/"))[2]
            for i in procs:
                try:
                    num = int(i)
                except:
                    continue
                ret.append(num)
            return ret

        listener_proc = ''
        listener_0 = list(map(clean, list(control(read_til, conn, "grep -l '.*listener.*' /proc/*/cmdline").strip().split('\n'))))
        listener_1 = list(map(clean, list(control(read_til, conn, "grep -l '.*argon2id.*' /proc/*/cmdline").strip().split('\n'))))
        for i in listener_1:
            if i in listener_0:
                listener_proc += str(i)
                listener_proc += ' '

        ssh = list(control(read_til, conn, "grep -l '.*/tmp/openssh.*' /proc/*/cmdline").split('\n'))[0]
        ssh_proc = list(ssh.split("/"))[2]
        goodbye = f"kill -9 {listener_proc}; kill -9 {ssh_proc}; exit"
        conn.sendline(goodbye.encode("utf-8"))

    def load_module(module_name, read_til, conn):
        module_path = f"modules/{module_name}/script.py"
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        data = {}
        for name, obj in globals().items():
            if name in config["modules"][module_name]["data_from_main"]:
                data[name] = obj

        for name, obj in locals().items():
            if name in config["modules"][module_name]["data_from_main"]:
                data[name] = obj

        ans = module.main(data)
        return ans

    threads = []
    for attack in data:
        port, id, password = attack["port"], attack["id"], attack["password"]
        thread = threading.Thread(target=worker, args=(port, local_results, id, password))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()




@app.route('/api/update/<int:id>', methods=["POST"])
def update(id):
    data = request.form['result']
    if request.method == 'POST':
        docker = Docker.query.filter_by(id=id).first()
        if docker:
            docker.vulnerabilities = data
            scan_id = docker.scan_id
            scan = Scans.query.filter_by(id=scan_id).first()
            docker.state = "finished"
            db.session.commit()
            if scan.mode == "offensive":
                scan.state = "finished"
                port = Ports.query.filter_by(port=docker.port).first()
                db.session.delete(port)
                db.session.commit()
            else:
                target = Docker.query.filter_by(scan_id=id).all()
                cnt = 0
                for container in target:
                    if container.state == "finished":
                        cnt += 1
                if cnt == len(target):
                    if scan.status == "one-time":
                        scan.state = "finished"
                        port = Ports.query.filter_by(port=docker.port).first()
                        db.session.delete(port)
                        db.session.commit()
                    elif scan.status == "recurring":
                        scan.state = "pending"
                    db.session.commit()
            return "Updated successfully", 200
        else:
            return "Docker entry not found", 404


@app.route('/api/start', methods=["POST"])
def start():
    uuid = request.form['scan_uuid']
    id = request.form['scan_id']
    if not Scans.query.filter_by(id=id, uuid=uuid).first():
        return "Error"


    myscan = Scans.query.filter_by(id=id, uuid=uuid).first()
    name, mode, data = myscan.name, myscan.mode, []
    print(f"Proceeding of {name} scan starts")
    target = Docker.query.filter_by(scan_id=id).all()

    for dockers in target:
        target_info = {
            "port": dockers.port,
            "id": dockers.id,
            "password": myscan.password
        }
        data.append(target_info)
        if dockers.state == "pending":
            dockers.state = "ongoing"

    db.session.commit()
    process = multiprocessing.Process(target=proceed_target, args=(data, mode, id))
    process.start()
    if myscan.state == "pending":
        myscan.state = "ongoing"
        db.session.commit()

    return "Scanning started"



if __name__ == '__main__':
    os.system("service ssh start")
    parse_modules()
    with app.app_context():
        db.create_all(bind_key='dckesc')
        db.create_all(bind_key='web')
    app.run(debug=False, port=2517, host="0.0.0.0")