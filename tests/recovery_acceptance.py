"""Root backup/restore acceptance inside the disposable runtime-test host."""
import importlib.util
import json
import os
import pathlib
import sqlite3
import subprocess
import tempfile
import unittest

SOURCE=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('recovery_manager',SOURCE / 'scripts/manage.py')
manage=importlib.util.module_from_spec(spec);spec.loader.exec_module(manage)

class RecoveryBundle(unittest.TestCase):
    def test_root_bundle_preserves_quota_key_and_database_and_rejects_tampering(self):
        if os.geteuid()!=0 or not pathlib.Path('/.dockerenv').exists():
            raise RuntimeError('This test requires the disposable Docker host')
        with tempfile.TemporaryDirectory(prefix='relaydeck-recovery-',dir='/run') as directory:
            root=pathlib.Path(directory);root.chmod(0o755)
            state=root / 'state';state.mkdir(mode=0o755)
            config=root / 'config';config.mkdir()
            releases=root / 'releases';releases.mkdir()
            release=releases / 'fixture';release.mkdir()
            (release / 'release.json').write_text('{"version":"fixture"}')
            for name in ('data','secrets','backups'):
                path=state / name;path.mkdir(mode=0o700);os.chown(path,1100,1100)
            (state / 'runtime').mkdir()
            manage.STATE=state;manage.CONFIG=config;manage.RELEASES=releases;manage.TRANSACTION=state / 'upgrade-transaction.json'
            policy=json.loads((SOURCE / 'deploy/broker.example.json').read_text())
            policy.update(database=str(state / 'data/relaydeck.db'),runtime_dir=str(state / 'runtime'),web_uid=1100,web_gid=1100,uid_start=62000)
            (config / 'broker.json').write_text(json.dumps(policy))
            (config / 'relaydeck.env').write_text(f'RELAYDECK_DATABASE={state}/data/relaydeck.db\nRELAYDECK_MFA_KEY={state}/secrets/mfa.key\n')
            (config / 'upgrade.json').write_text('{"owner_id":1,"web_uid":1100,"web_gid":1100}')
            (config / 'installation.json').write_text('{"units":{}}')
            manage.as_web(manage.BIN,'migrate');manage.as_web(manage.BIN,'init-key')
            database=state / 'data/relaydeck.db'
            def db(sql):
                code="import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.executescript(sys.argv[2]);c.close()"
                subprocess.run(['runuser','-u','relaydeck','--','python3','-c',code,str(database),sql],check=True)
            db("INSERT INTO users(id,username,password_hash,role,port_start,port_end,max_rules,created_at) VALUES(1,'owner','hash','admin',1024,65535,10,1);")
            snapshot=state / 'backups/update-12345'
            db("INSERT INTO sessions(token_hash,user_id,csrf_token,auth_version,expires_at,created_at) VALUES('old-session',1,'old-csrf',1,9999999999,1)")
            manage.as_web(manage.BIN,'backup',str(snapshot))
            key=(state / 'secrets/mfa.key').read_bytes()
            # Create a valid initial ledger, then add usage that exists only in
            # kernel counters. The backup must absorb this final traffic.
            manage.run(str(manage.BIN),'checkpoint-traffic',str(config / 'broker.json'))
            ledger=json.loads((state / 'runtime/traffic-ledger.json').read_text())
            period=ledger['period']
            ledger['accounts']={'1':{'budget':{'limit_bytes':1000,'mode':'both'},'incoming':100,'outgoing':20,'charged':120,'applied':None,'prepared':False}}
            (state / 'runtime/traffic-ledger.json').write_text(json.dumps(ledger))
            # Remove only the fixture's newer shadow so this emulates v0.3.1.
            (state / 'runtime/traffic-subscriptions.json').unlink()
            manage.run('nft','add','table','inet','relaydeck_usage')
            manage.run('nft','add','counter','inet','relaydeck_usage',f'rx_1_{period}','{','packets','1','bytes','456',';','}')
            manage.run('nft','add','table','inet','unrelated_qa')
            record={'backup':str(snapshot),'previous':str(release),'phase':'backed_up'}
            manage.atomic_json(manage.TRANSACTION,record)
            manage.prepare_recovery()
            bundle=manage.recovery_directory(snapshot)
            manifest=manage.verify_recovery(bundle)
            self.assertTrue({'relaydeck.db','mfa.key','traffic-ledger.json','traffic-subscriptions.json','upgrade.json'}<=manifest['files'].keys())
            saved=json.loads((bundle / 'traffic-subscriptions.json').read_text())
            self.assertEqual(saved['accounts']['1']['incoming'],456)
            db("UPDATE users SET username='changed'")
            (state / 'secrets/mfa.key').write_bytes(b'a'*64)
            manage.restore_recovery(bundle, revoke_sessions=True)
            with sqlite3.connect(database) as connection: self.assertEqual(connection.execute('SELECT username FROM users').fetchone()[0],'owner')
            with sqlite3.connect(database) as connection: self.assertEqual(connection.execute('SELECT COUNT(*) FROM sessions').fetchone()[0],0)
            self.assertEqual((state / 'secrets/mfa.key').read_bytes(),key)
            self.assertEqual((state / 'secrets/mfa.key').stat().st_uid,1100)
            self.assertEqual((state / 'secrets/mfa.key').stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads((state / 'runtime/traffic-subscriptions.json').read_text())['accounts']['1']['incoming'],456)
            tables=json.loads(manage.run('nft','-j','list','tables',capture=True))
            self.assertIn('unrelated_qa',json.dumps(tables));self.assertNotIn('relaydeck_usage',json.dumps(tables))
            # An unprivileged application cannot alter the root recovery point.
            denied=subprocess.run(['runuser','-u','relaydeck','--','test','-w',str(bundle / 'traffic-subscriptions.json')])
            self.assertNotEqual(denied.returncode,0)
            (bundle / 'traffic-subscriptions.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'integrity'):manage.verify_recovery(bundle)

if __name__=='__main__':unittest.main()
