#!/usr/bin/env python
# -*- coding:utf8 -*-
__author__ = 'xiaozhang'
import time
import threading
import json
from codeigniter import ci
from codeigniter import CI_Application

class Task(object):
    def __init__(self):
        self.RESULT_LIST_KEY='results'
        self.has_result2db=False
        self._cmdb=None
        self.server=''
        pass
    def _init_cmdb(self):
        if self._cmdb==None:
            self._cmdb=ci.loader.cls("CI_DB")(**ci.config.get('cmdb'))
    def _result2db(self):
        if self.has_result2db:
            return 'ok'
        else:
            self.has_result2db=True
        def _tmp():
            rows=[]
            batlen=20
            inner_timer=time.time()
            while True:
                try:
                    self._init_cmdb()
                    now=time.time()
                    snow= time.strftime( '%Y-%m-%d %H:%M:%S',time.localtime(now))
                    js= ci.redis.rpop(self.RESULT_LIST_KEY)
                    if js!=None or len(rows)>0:
                        if js!=None:
                            row=json.loads(js)
                            rows.append(row)
                        if len(rows)>=batlen or (len(rows)>0 and time.time()-inner_timer>3):
                            inner_timer=time.time()
                            update_sqls=[]
                            update_data=[]
                            insert_sqls=[]
                            insert_data=[]
                            insert_sql='''
                                    INSERT INTO ops_results
                                        (
                                        task_id,
                                        cmd,
                                        result,
                                        ctime,
                                        op_user,
                                        uuid,
                                        sys_user
                                        )
                                        VALUES
                                        (
                                        '{task_id}',
                                        '{cmd}',
                                        '{result}',
                                        '{ctime}',
                                        '{op_user}',
                                        '{uuid}',
                                       '{sys_user}'
                                        )

                             '''
                            update_sql='''


                                    UPDATE ops_results
                                        SET
                                        result = '{result}' ,
                                        utime = '{utime}'
                                        WHERE
                                        task_id = '{task_id}'

                                '''
                            for row in rows:
                                if 'user' in row:
                                    data={'op_user':row['user'],'ctime':row['ctime'],'cmd':row['cmd'],'task_id':row['task_id'],'uuid':row['uuid'],'result':'','sys_user':row.get('sys_user','')}
                                    insert_data.append(data)
                                else:
                                    data={'task_id':row['task_id'],'result':row['result'],'utime':row['utime']}

                                    update_data.append(data)

                            if len(insert_data)>0:
                                self._cmdb.batch(insert_sql,insert_data)
                            if len(update_data)>0:
                                self._cmdb.batch(update_sql,update_data)
                            # cnt=ci.redis.llen(self.RESULT_LIST_KEY)
                            # if cnt==None:
                            #     cnt=0
                            # if cnt>50:
                            #     batlen=int(cnt/5)
                            # else:
                            #     batlen=cnt
                            rows=[]
                    else:
                        time.sleep(1)
                except Exception as er:
                    ci.logger.error(rows)
                    ci.logger.error(er)
        # threading.Thread(target=_tmp).start()
        _tmp()
        return 'ok'

    def repair(self):
        while True:
            try:
                ci.request( self.server+'/cli/repair')
                time.sleep(60*3)
            except Exception as er:
                ci.logger.error(er)
                time.sleep(60*3)

    def hb2db(self):
        while True:
            try:
                ret=ci.request( self.server+'/cli/hb2db')
                time.sleep(60)
            except Exception as er:
                ci.logger.error(er)
                time.sleep(60)

    def hbstatus(self):
        while True:
            try:
                self._init_cmdb()
                self._cmdb.query("UPDATE ops_heartbeat SET utime=NOW() WHERE ISNULL(utime) OR utime=''")
                time.sleep(1)
                self._cmdb.query("UPDATE ops_heartbeat SET `status`='offline' WHERE (UNIX_TIMESTAMP(NOW())-60*10) >  UNIX_TIMESTAMP(utime)")
                time.sleep(60)
            except Exception as er:
                ci.logger.error(er)
                time.sleep(60)




if __name__ == '__main__':
    CI_Application(r'./')
    task=Task()
    host=ci.config.get('server').get('host')
    if host=='0.0.0.0':
        host='127.0.0.1'
    task.server= 'http://%s:' %( host) + str(ci.config.get('server').get('port'))
    threading.Thread(target=task.repair).start()
    threading.Thread(target=task.hb2db).start()
    threading.Thread(target=task.hbstatus).start()
    task._result2db()

