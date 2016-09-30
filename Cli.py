#!/usr/bin/env python
# -*- coding:utf8 -*-
__author__ = 'xiaozhang'


from codeigniter import ci
from codeigniter import cache
from codeigniter import CI_Cache
import os
import json
import re
import sys
import time
import base64
import datetime
# from sql4json.sql4json import *

import threading






def auth(func):
    def decorated(*arg,**kwargs):
        if not 'HTTP_AUTH_UUID' in ci.local.env:
            return "(error)unauthorize1"
        if ci.redis.get('login_'+ci.local.env['HTTP_AUTH_UUID'])==None:
            return "(error)unauthorize"
        return func(*arg,**kwargs)
    return decorated





class HeartBeat(object):

    _singleton=False

    def __init__(self):
        self.filename='heartbeat.json'
        self.data=[]# {'uuid','status','utime','salt','ips','hostname','system_os','ip'}
        self.load_data()
        self.uuids=set()


    def ip2uuid(self,data):
        if 'ips' in data.keys():
            p=ci.redis.pipeline()
            for ip in data['ips'].split(','):
                if ip!='127.0.0.1':
                    p.sadd(ip,data['uuid'])
            p.execute()



    def check_online(self):
        while True:
            try:
                self.check_status()
                time.sleep(60*2)
            except Exception as er:
                pass


    def confirm_offline(self,uuid=''):
        self.check_status()
        offline=[]
        result=[]
        for d in self.data:
            if d['status']=='online':
                result.append(d)
            elif d['status']=='offline':
                offline.append(d['uuid'])
        self.data=result
        self.dump_data()
        p=ci.redis.pipeline()
        if uuid!='':
            if uuid in offline:
                ci.redis.srem('uuids',uuid)
                return 'ok'
            else:
                return '(error) %s is not in offline status' %(uuid)
        for off in offline:
            p.srem('uuids',off)
        p.execute()
        return 'ok'


    def check_status(self):
        uuids=ci.redis.smembers("uuids")
        p=ci.redis.pipeline()
        for i in uuids:
            p.get(i)
        self.data= map(lambda x:json.loads(x),p.execute())

        now=int(time.time())
        for d in self.data:
            if now-d['utime']>60*10:
                d['status']='offline'




    def status(self):

        self.check_status()
        result={'offline':0,'online':0,'count':0}
        for d in self.data:
            result['count']= result['count']+1
            if d['status']=='offline':
                result['offline']=result['offline']+1
            elif  d['status']=='online':
                result['online']=result['online']+1
        return  result

    def listclient(self):
        self.check_status()
        result=[]
        fields=['status','uuid','utime','ip','hostname']
        for row in self.data:
            d={}
            for i in fields:
                d[i]=row[i]
            d['utime']=  time.strftime( '%Y-%m-%d %H:%M:%S',time.localtime(d['utime']))
            result.append(d)
        return  result


    def _status_line(self,status='offline'):
        self.check_status()
        result=[]
        for d in self.data:
            if d['status']==status:
                d['utime']=  time.strftime( '%Y-%m-%d %H:%M:%S',time.localtime(d['utime']))
                if 'ips' in d:
                    del d['ips']
                result.append(d)
        return  result


    def offline(self):
        return self._status_line(status='offline')


    def online(self):
        return self._status_line(status='online')




    def getetcd(self,param):
        return {'server':['10.3.155.104:4001'],'prefix':'/keeper'}
        return {'server':['172.16.119.110:4001'],'prefix':'/keeper'}
        return {'server':['172.16.119.3:4001'],'prefix  ':'/keeper'}



    # @cache.Cache()
    def heartbeat(self,params):
        status=''
        hostname=''
        ip=''
        if 'status'  in params.keys():
            status=params['status'].strip()

        if 'uuid' not in params.keys() and  len(params['uuid'])!=36:
            self.remove(params['uuid'])
            return '(error) invalid request'
        if 'hostname' in params.keys():
            hostname=params['hostname']
        if 'ip' in params.keys():
            ip=params['ip']

        objs=self.get_product_uuid(params['uuid'])
        # self.uuids.add(params['uuid'])
        ci.redis.sadd('uuids',params['uuid'])

        salt= str(ci.uuid())
        utime=int(time.time())

        if objs==None or len(objs)==0:
            param={'uuid':params['uuid'],'salt':salt,'ips':params['ips'],'utime':utime,'status':'online','status_os':status,'hostname':hostname,'ip':ip}
            # self.data.append(param)
            ci.redis.set(params['uuid'],json.dumps(param))
            # self.ip2uuid( param)
        elif len(objs)==1:
            if 'salt' in objs[0].keys():
                salt=objs[0]['salt']
            param={'uuid':params['uuid'],'salt':salt,'ips':params['ips'],'utime':utime,'status':'online','status_os':status,'hostname':hostname,'ip':ip}
            # self.ip2uuid(param)
            ci.redis.set(params['uuid'], json.dumps( param))
        else:
            ci.logger.error('heartbeat double: uuid=%s,ips=%s'%(params['uuid'],params['ips']))


        etcd=self.getetcd(params)

        if status!='':
            return {'etcd':etcd, 'salt':salt}
        else:
            return {'etcd':etcd, 'salt':salt,'shell':self.shellstr()}



    def get_product_uuid(self,ip):
        ret=[]
        if len(ip)>16:
            objs=ci.redis.get(ip)
            if objs!=None:
                ret.append(json.loads(objs))

        if len(ret)>0 or len(ip)>16:
            return ret
        else:
            self.check_status()
            objs=ci.loader.helper('DictUtil').query(self.data,select='*',where="((ips in %s) or (uuid=%s))"% (ip,ip))
            return objs

    def load_data(self):
        if os.path.isfile(self.filename):
            with open(self.filename,'r') as file:
                self.data=json.loads( file.read())

    def dump_data(self):
        with open(self.filename,'w+') as file:
            file.write(json.dumps(self.data))

    def shellstr(self):
        shell='''
#!/bin/sh
disk=`df | awk 'BEGIN{total=0;avl=0;used=0;}NR > 1{total+=$2;used+=$3;avl+=$4;}END{printf"%d", used/total*100}'`
#mem=`top -b -d 1 -n 2 | grep -w Mem | awk 'END{printf"%d",$4/$2*100}'`
mem=`free |grep -w "Mem:" |awk '{printf"%d", $3/$2*100}'`
cpu=`top -b -n 2 -d 1 | grep -w Cpu |awk -F ',|  ' 'END{print $2+$3}'`
net=`ss -s |grep -w 'Total:'|awk '{print $2}'`
iowait=`top -n 2 -b -d 1  |grep -w 'Cpu' |awk '{print $6}'|awk -F '%' 'END {print $1}'`
load=`top -n 2 -d 1  -b |grep -w average: |awk -F',' 'END{printf"%3.2f",$5}'`
echo '{"cpu":'$cpu,'"disk":'$disk,'"mem":'$mem,'"net":'$net,'"iowait":'$iowait,'"load":'$load }
        '''
        return shell

class Cli:

    def __init__(self):
        self.cmdkeys={}
        self.HEARTBEAT_LIST_KEY='heartbeats'
        self.RESULT_LIST_KEY='results'
        self.TASK_LIST_KEY='indexs'
        self.CMDB_OPTION_PREFIX='cmdb_options_'
        self._cmdb=None
        self.hb=HeartBeat()
        self.has_hd2db=False
        self.has_result2db=False

    def index(self,req,resp):
        return "ok"

    def abc(self,param='',**kwargs):
        # print ci.local.env
        #ci.set_header('WWW-Authenticate','Basic realm="Authentication System"')
        #ci.set_header('HTTP/1.0 401 Unauthorized')
        # sys.exit(0)
        print kwargs
        return "hello world".strip()

    def help(self,req,resp):
        h='''
        ########## 文件与shell ##############

        cli upgrade   更新 cli 程序
        cli shell -f filename -a "shell 参数"  下载并接行shell指令
        cli listfile   查看文件列表
        cli upload -f filename [-d directory] 上传文件
        cli download -f filename [-d directory] [-o path/to/save]  下载文件
        cli delfile -f filename -k key  删除文件

        ########## 环境变量 ##############

        cli addenv -k key -v value  -g group (default)  增加环境变量
        cli getevn  -k key -g group (default) 获取环境变量
        cli delenv   -k key -g group 删除环境变量
        cli listenv   -g group -e 1 查看某个组的环境变量 默认 default -e 1 导出
        cli updateenv   -k key -v value -g group (default)更新环境变量

        ########## CMDB ##############

        cli cmdb -t tag=value -f fields 按tag过滤cmdb中的数据,tag参考下面说明,参考下例
        cli cmdb  -t 'business=flymeos and ip=221.5.97.186'
             (tag 必须是 business,container,domain,ip,room_en_short,module)
        cli select  -t 'business=flymeos and ip=221.5.97.186' 取得cmdb中的IP,为批量作基础

         '''
        return h

    def feedback_result(self,req,resp):
        param=req.params['param']
        data=json.loads(param)
        if 'index' in data.keys() and str(data['index']) in ci.redis.smembers(self.TASK_LIST_KEY):
            # self.cmdkeys[str(data['index'])]=data['result']
            try:
                pl=ci.redis.pipeline()
                pl.setex(str(data['index']),60*5,data['result'])
                dd={}
                dd['utime']=int(time.time())
                dd['task_id']=str(data['index'])
                if data['result']=='13800138000':
                    dd['result']='(error) time out'
                dd['result']=data[u'result']
                pl.lpush(self.RESULT_LIST_KEY,json.dumps(dd))
                pl.ltrim(self.RESULT_LIST_KEY,0,20000)
                pl.srem(self.TASK_LIST_KEY,str(data['index']))
                pl.execute()
            except Exception as er:
                print(er)
                ci.logger.error(er)
                pass

        ci.logger.info("index:%s,ip:%s,result:\n%s"%(str(data['index']), data['ip'],data['result']))

    def uuid(self,req,resp):
        return ci.uuid()

    def listclient(self,req,resp):
        return self.hb.listclient()

    def _check_server(self, address, port):
        import socket
        s = socket.socket()
        print "Attempting to connect to %s on port %s" % (address, port)
        try:
            s.settimeout(5)
            s.connect((address, port))
            print "Connected to %s on port %s" % (address, port)
            return True
        except socket.error, e:
            print "Connection to %s on port %s failed: %s" % (address, port, e)
            return False
        finally:
            try:
                s.close()
            except Exception as er:
                pass

    def md5(self,req,resp):
        params=self._params(req.params['param'])
        return ci.md5(params['s'])




    def heartbeat(self,req,resp):
        client_ip=self._client_ip(req)
        params=self._params(req.params['param'])
        if not 'ips' in params.keys():
            return '(error) invalid ips'
        if not client_ip in params['ips'].split(','):
            ci.logger.info(client_ip+' attack server ')
            return '(error) invalid client_ip'
        if not 'hostname' in params.keys():
            params['hostname']='unknown'
        params['ip']=client_ip
        p=ci.redis.pipeline()
        p.lpush(self.HEARTBEAT_LIST_KEY,json.dumps(params))
        p.ltrim(self.HEARTBEAT_LIST_KEY,0,5000)
        p.execute()
        return self.hb.heartbeat(params)

    def hb2db(self,req,resp):
        return  self._hb2db()

    def _hb2db(self):
        if self.has_hd2db:
            return 'ok'
        else:
            self.has_hd2db=True
        def _tmp():
            rows=[]
            batlen=1
            while True:
                try:
                    self._init_cmdb()
                    now=time.time()
                    snow=  time.strftime( '%Y-%m-%d %H:%M:%S',time.localtime(now))
                    js= ci.redis.lpop(self.HEARTBEAT_LIST_KEY)
                    if js!=None:
                        row=json.loads(js)
                        rows.append(row)
                        if len(rows)>=batlen:
                            sqls=[]
                            ds=[]
                            for row in rows:
                                data={'uuid':row['uuid'],'status':'online','utime':snow,'hostname':row['hostname'],'ip':row['ip']}
                                ds.append(data)

                            sql='''

                            REPLACE INTO ops_heartbeat
                                (UUID,
                                hostname,
                                ip,
                                utime,
                                STATUS
                                )
                                VALUES
                                ('{uuid}',
                                '{hostname}',
                                '{ip}',
                                '{utime}',
                                '{status}'
                                )
                            '''

                            self._cmdb.batch(sql,ds)
                            cnt=ci.redis.llen(self.HEARTBEAT_LIST_KEY)
                            if cnt==None:
                                cnt=0
                            if cnt>50:
                                batlen=int(cnt/5)
                            else:
                                batlen=cnt
                            rows=[]
                    else:
                        time.sleep(10)
                except Exception as er:
                    ci.logger.error(er)
        threading.Thread(target=_tmp).start()
        return 'ok'
    def result2db(self,req,resp):
        return self._result2db()

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
                                        uuid
                                        )
                                        VALUES
                                        (
                                        '{task_id}',
                                        '{cmd}',
                                        '{result}',
                                        '{ctime}',
                                        '{op_user}',
                                        '{uuid}'
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
                                    data={'op_user':row['user'],'ctime':row['ctime'],'cmd':row['cmd'],'task_id':row['task_id'],'uuid':row['uuid'],'result':''}
                                    insert_data.append(data)
                                else:
                                    data={'task_id':row['task_id'],'result':row['result'],'utime':row['utime']}
                                    update_data.append(data)

                            if len(insert_data)>0:
                                self._cmdb.batch(insert_sql,insert_data)
                                time.sleep(0)
                            if len(update_data)>0:
                                self._cmdb.batch(update_sql,update_data)
                                time.sleep(0)
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
        threading.Thread(target=_tmp).start()
        return 'ok'


    def status(self,req,resp):
        return self.hb.status()

    @auth
    def offline(self,req,resp):
        return self.hb.offline()
    @auth
    def online(self,req,resp):
        return self.hb.online()

    def dump_heartbeat(self,req,resp):
        self.hb.dump_data()
        return 'ok'

    @auth
    def suicide(self,req,resp):
        pass

    def _repair(self,ip):
        key_filename =ci.config.get('repair')['key_filename']
        password=ci.config.get('repair')['password']
        user=ci.config.get('repair')['user']
        port=ci.config.get('repair')['port']
        cmd='sudo wget http://10.3.155.104:8005/cli/upgrade -O /bin/cli && sudo  chmod +x  /bin/cli && sudo  /bin/cli daemon -s restart'
        return self._remote_exec(ip,cmd,user=user,password=password,port=port,key_file=key_filename)


    def repair(self,req,resp):
        port=ci.config.get('repair')['port']
        params=self._params(req.params['param'])
        if 'ip' in params:
            ip=params['ip']
            return self._repair(ip)
        rows=self.hb.offline()
        ips=set()
        for row in rows:
            ips.add(str(row['ip']))
            # _ips=row['ip'].split(',')
            # for i in _ips:
            #     if i.startswith('10.'):
            #         if self._check_server(i,port):
            #             ips.add(i)
            #             break
        ret=''
        for i in ips:
            ret+="repair ip:"+ i+"\n" +self._repair(i)
        ci.logger.info(ret)
        return ret+"\nfinish"

    @auth
    def confirm_offline(self,req,resp):
        params=self._params(req.params['param'])
        if 'uuid' in params:
            return self.hb.confirm_offline(params['uuid'])
        else:
            return self.hb.confirm_offline()


    def _cmd(self,ip,cmd,timeout=10,user='root',async="0"):
        try:
            etcd=self.hb.getetcd(ip)
            import urllib2,urllib
            objs=self.hb.get_product_uuid(ip)
            salt=''
            puuid=''
            if objs==None  or len(objs)==0:
                return '(error) invalid ip'
            elif len(objs)==1:
                puuid=objs[0]['uuid']
                salt=objs[0]['salt']
                now=int(time.time())
                if objs[0]['status']=='offline' or  now-objs[0]['utime']>60*10:
                    return '(error) client status offline'
            elif len(objs)>1:
                return '(error) too many ip matched'

            if puuid=='' or salt=='':
                return '(error)client not online'
            cmd="su '%s' -c \"%s\"" %(user, cmd.encode('utf-8').replace('"','\\"'))
            data_raw={'cmd':cmd.encode('utf-8'),'md5': ci.md5(cmd.encode('utf-8') +str(salt)),'timeout':str(timeout),'user':user}
            data={'value': json.dumps( data_raw) }
            data=urllib.urlencode(data)
            req = urllib2.Request(
                    url ="http://%s/v2/keys%s/servers/%s/"%(etcd['server'][0],etcd['prefix'],puuid),
                    data=data
            )
            req.get_method = lambda: 'POST'
            # print urllib2.urlopen(req,timeout=10).read()
            ret=json.loads(urllib2.urlopen(req,timeout=10).read())



            # print ret
            index=str(ret['node']['createdIndex'])
            self.cmdkeys[index]=''
            #ci.redis.sadd('indexs',index)
            # pl=ci.redis.pipeline()
            ci.redis.sadd(self.TASK_LIST_KEY,index)

            start=time.time()
            if async=='1':
                return index
            if json.loads(ret['node']['value'])['cmd']==cmd:
                del data_raw['md5']
                del data_raw['timeout']
                data_raw['task_id']=index
                data_raw['ctime']=int(start)
                data_raw['uuid']=ip
                data_raw['result']=''
                ci.redis.lpush(self.RESULT_LIST_KEY,json.dumps(data_raw))


                # pl.execute()
                while True:
                    if (time.time()-start> timeout) or self.cmdkeys[index]!='':
                        #ci.redis.srem(self.TASK_LIST_KEY,index)
                        pass
                        break
                    else:
                        time.sleep(0.5)
                        ret=ci.redis.get(index)
                        if ret!='' and ret!=None:
                            #ci.redis.srem(self.TASK_LIST_KEY,index)
                            try:
                                return ret.encode('utf-8')
                            except Exception as er:
                                # if isinstance(ret,basestring):
                                #     return json.dumps(ret)
                                return ret.decode('utf-8','ignore')
                return '(success) submit command success,job id:%s'% (index)
            else:
                return '(unsafe) submit command success '
        except Exception as er:
            print er
            return 'fail'
            pass

    def _is_while_ip(self,ip):
        wip=ci.config.get('white_ips',['127.0.0.1'])
        if ip in wip:
            return True
        else:
            return False
        pass

    def _is_web_while_ip(self,ip):
        wip=ci.config.get('web_white_ips',['127.0.0.1'])
        if ip in wip:
            return True
        else:
            return False
        pass


    def _client_ip(self,req):
        return req.env['REMOTE_ADDR']



    def cmd_result(self,req,resp):
        params=self._params(req.params['param'])
        if not 'i' in params.keys():
            return '-i(index) is required'
        return  ci.redis.get(params['i'])


    def _valid_cmd(self,cmd=''):
        keys=['shutdown','reboot','halt','poweroff','int','rm']
        cmds=cmd.split('|')
        for c in cmds:
            cc=c.strip().split(" ")
            if len(cc)>0:
                if cc[0] in keys:
                    return False
        return True


    def web_cmd(self,req,resp):
        client_ip=req.env['REMOTE_ADDR']
        if not self._is_web_while_ip(client_ip):
            return '(error) ip is not in white list.'
        params=self._params(req.params['param'])
        md5=params['md5']
        timestamp=params['ts']
        key=ci.config.get('web_key')
        if ci.md5(key+str(timestamp))!=md5:
            return '(error) sign error!'
        return self._inner_cmd(req,resp,True)

    @auth
    def cmd(self,req,resp):
        client_ip=req.env['REMOTE_ADDR']
        op_user=ci.redis.get('login_'+req.env['HTTP_AUTH_UUID'])
        if not self._is_while_ip(client_ip):
            return '(error) ip is not in white list.'
        params=self._params(req.params['param'])

        return self._inner_cmd(req,resp)


    def _inner_cmd(self,req,resp,web_cmd=False):
        client_ip=req.env['REMOTE_ADDR']
        op_user=''
        params=self._params(req.params['param'])
        cmd=''
        ip=''
        user='root'
        timeout=25
        async='0'
        out='text'
        if  'c' in params:
            cmd=params['c']
        else:
            return '-c(cmd) require'
        if  'i' in params:
            if not web_cmd:
                ip=params['i']+','
            else:
                ip=params['i']
        else:
            return '-i(ip) require'
        if  't' in params:
            timeout= float( params['t'])
        if  'u' in params:
            user= params['u']
        if  'o' in params:
            out= params['o']
            if out not in ['json','text']:
                return '-o(output) must be text or json'
        if not self._valid_cmd(cmd):
            return '-c(cmd) is danger'
        if  'async' in params:
            async= params['async']
        lg={'op_user':op_user,'from_ip':client_ip,'to_ip':ip,'user':user,'cmd':cmd}
        ci.logger.info(json.dumps(lg))
        result={}
        failsip=[]

        def task(q):
            while True:
                if not tqs.empty():
                    i=tqs.get()
                    result[i]=self._cmd(i,cmd,timeout=timeout,user=user,async=async)
                    gevent.sleep(0)
                else:
                    break
        ip2uuid={}
        uuid2ip={}
        ipset=set()
        if web_cmd:
            import gevent
            import gevent.queue
            tqs= gevent.queue.Queue()
            ips=json.loads(ip)
            for x in ips:
                ip2uuid[x['ip']]=x['uuid']
                uuid2ip[x['uuid']]=x['ip']
                ipset.add(x['uuid'])
            map(lambda x:tqs.put(x),ipset)
            tlen=tqs.qsize() if  tqs.qsize()<100 else 100
            threads = [gevent.spawn(task,tqs) for i in xrange(tlen)]
            gevent.joinall(threads)

        elif ip.find(',')!=-1:
            import gevent
            import gevent.queue
            tqs= gevent.queue.Queue()
            ips=ip.split(',')
            self.hb.status()

            for row in self.hb.data:
                for i in row['ips'].split(','):
                    i=str(i)
                    if i.strip()!='' and i in ips:
                        ip2uuid[str(i)]=row['uuid']
                        uuid2ip[str(row['uuid'])]=str(i)
            for i in ips:
                if i in ip2uuid.keys():
                    # tqs.put(ip2uuid[i])
                    ipset.add(ip2uuid[i])
                else:
                    if len(i)==36:
                        # tqs.put(i)
                        ipset.add(i)
                    else:
                        failsip.append(i)
                # result[i]=self._cmd(i,cmd,timeout=timeout,user=user,async=async)
            map(lambda x:tqs.put(x),ipset)
            tlen=tqs.qsize() if  tqs.qsize()<100 else 100
            threads = [gevent.spawn(task,tqs) for i in xrange(tlen)]
            gevent.joinall(threads)
        else:
            result[ip]= self._cmd(ip,cmd,timeout=timeout,user=user,async=async)

        if out=='text':
            ret=[]
            for i in result:
                ret.append('-'*80)
                if len(i)<32 or len(uuid2ip)==0:
                    ret.append(i)
                else:
                    ret.append(uuid2ip[i])
                ret.append(result[i])
            if len(failsip)>0:
                return "\n".join(ret)+"\nfails:\n"+"\n".join(failsip)
            return "\n".join(ret)
        elif out=='json':
            return result

        return result



    def cmdb(self,req,resp):
        params=self._params(req.params['param'])
        select='*'
        where=''
        if 'f' in params:
            select=params['f']
        if 't' in params:
            where=params['t']
        if where=='':
            return '-t(tag) is required'
        return self._cmdb_api(select.encode('utf-8'),where.encode('utf-8'))

    def load_cmdb(self,req,resp):
        with open('cmdb.json') as file:
            js=file.read()
            ci.redis.set('cmdb',json.dumps(json.loads(js)))
            return 'ok'

    def _init_cmdb(self):
        if self._cmdb==None:
            self._cmdb=ci.loader.cls("CI_DB")(**ci.config.get('cmdb'))


    def load_cmdb2db(self,req,resp):
        self._init_cmdb()
        ret=ci.redis.get('cmdb')
        if ret!=None:

            rows=json.loads(ret)
            sql='''

                REPLACE INTO ops_cmdb
                    (room,
                    business,
                    container,
                    module,
                    ip,
                    domain
                    )
                    VALUES
                    ('{room_en_short}',
                    '{business}',
                    '{container}',
                    '{module}',
                    '{ip}',
                    '{domain}'

                    )
                '''
            # self._cmdb.batch(sql,rows)
            for row in rows:
                try:
                    self._cmdb.query(sql,row)
                except Exception as er:
                    pass
            return 'ok'
        else:
            return '(error) cmdb is None'


    def _cmdb_options(self,type):
        ret=ci.redis.get(self.CMDB_OPTION_PREFIX+type)
        if ret!=None:
            return json.loads(ret)
        else:
            js=ci.redis.get('cmdb')
            rows=json.loads(js)
            t_set=set()
            for row in rows:
                if type in row and row[type]!=None and row[type]!='':
                    t_set.add(row[type])
            l_set=list(t_set)
            ci.redis.set(self.CMDB_OPTION_PREFIX+type,json.dumps(list(l_set)))
            return sorted(l_set)

    def cmdb_options(self,req,resp):
        params=self._params(req.params['param'])
        rows= self._cmdb_options(params['t'])
        ret=[]
        for val in rows:
            ret.append({'text':val,'value':val})
        return {'reply':ret}


    def _cmdb_api(self,select,where):
        js=ci.redis.get('cmdb')
        cmdb=json.loads(js)
        return ci.loader.helper('DictUtil').query(cmdb,select=select,where=where)

    def select(self,req,resp):
        params=self._params(req.params['param'])
        where=''
        if 't' in params:
            where=params['t']
        if where=='':
            return '-t(tag) is required'
        rows=self._cmdb_api('ip',where)
        rows=filter(lambda x:x['ip'].startswith('10.') or
                             x['ip'].startswith('172.16') or
                             x['ip'].startswith('192.168.'),rows )
        ips=set()
        map(lambda x:ips.add(x['ip']),rows)
        return ",".join(ips)



    def _get_login_user(self,req):
        opuser=ci.redis.get('login_'+ci.local.env['HTTP_AUTH_UUID'])
        return opuser

    def _is_super_user(self,req):
        opuser=self._get_login_user(req)
        super_users=ci.config.get('super_users',['jqzhang'])
        if opuser in super_users:
            return True
        else:
            return False
    @auth
    def disableuser(self,req,resp):
        if not self._is_super_user(req):
            return '(error) user not permit'
        return self._userstatus(req.params['param'],0)

    @auth
    def enableuser(self,req,resp):
        if not self._is_super_user(req):
            return '(error) user not permit'
        return self._userstatus(req.params['param'],1)
    def _userstatus(self,param, status):
        # opuser=ci.redis.get('login_'+ci.local.env['HTTP_AUTH_UUID'])

        params=self._params(param)
        user=''
        uuid='(error) not login'
        if  'u' in params:
            user=params['u']
        else:
            return '-u(user) require'
        data={'user':user,'status':status}
        ci.db.query("update user set status='{status}' where user='{user}'",data)
        return 'success'


    def dispatch_cmd(self,req,resp):
        params=self._params(req.params['param'])
        if 'i' not in params:
             return '-i(ip) require'

        return 'ls /data';


    def _check_user(self,req,register=True):
        params=self._params(req.params['param'])
        user=''
        pwd=''
        opwd=''
        ip=''
        if  'u' in params:
            user=params['u']
        else:
            return False, '-u(user) require'
        if  'p' in params:
            pwd=params['p']
        else:
            return False, '-p(password) require'

        if 'o' in params:
            opwd=params['o']
        if 'i' in params:
            ip=params['i']
        return True,{'user':user,'pwd':pwd,'opwd':opwd,'ip':ip}

    def register(self,req,resp):
        ok,data=self._check_user(req)
        if not ok:
            return data

        if data['opwd']!='':
            ok,msg=self._login(data['user'],data['opwd'],data['ip'])
            if ok:
                data['pwd']=ci.md5(data['pwd'])
                ci.db.query("update user set  pwd='{pwd}',ip='{ip}' where user='{user}'",data)
                return 'success'
            else:
                return '-o(old password) is error'


        if ci.db.scalar("select count(1) as cnt from user where user='{user}'",data)['cnt']>0:
            return "(error)user exist"
        data={'user':data['user'],'pwd':ci.md5(data['pwd']) }
        ci.db.query("insert into user(user,pwd) values('{user}','{pwd}')",data)
        return 'success'


    def _login(self,user,pwd,ip):
        data={'user':user,'pwd':ci.md5(pwd)}
        is_exist=ci.db.scalar("select status from user where user='{user}' and pwd='{pwd}' limit 1 offset 0",data)
        udata={'user':user,'lasttime':time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(time.time())),'ip':ip}
        if is_exist!=None:
            if is_exist['status']!=1:
                return False,'(error)user status disabled'
            ci.db.query("update user set logincount=logincount+1,lasttime='{lasttime}',ip='{ip}' where user='{user}'",udata)
            return True,'success'
        else:
            ci.db.query("update user set logincount=logincount+1,failcount=failcount+1,lasttime='{lasttime}',ip='{ip}' where user='{user}'",udata)
            return False,'(error) user or password is error'



    def login(self,req,resp):
        ok,data=self._check_user(req)
        if not ok:
            return data
        ok,msg=self._login(data['user'],data['pwd'],data['ip'])
        if ok:
            uuid=ci.uuid()
            ci.redis.setex('login_'+uuid,5*60,data['user'])
            return str(uuid)
        else:
            return msg


    def shell(self,req,resp):
        dir=req.params.get('dir','shell')
        file=req.params.get('file','')
        dir=dir.replace('..','').replace('.','').replace('/','')
        path= 'files'+ os.path.sep+ dir+ os.path.sep + file
        if os.path.isfile(path):
            return open(path,'rb').read()
        else:
            return "#!/bin/bash\n echo '(error) file not found'"


    def upgrade(self,req,resp):
        if os.path.isfile('cli.mini'):
            return open('cli.mini').read()
        else:
            return open('cli').read()

    def _params(self,param='{}',opts=''):
        params= json.loads(param)
        return params

    def listfile(self,req,resp):
        params=self._params(req.params['param'])
        if 'd' in params:
            directory=params['d']
        else:
            directory=''
        directory=directory.replace('.','')
        return "\n".join(os.listdir('files/'+directory))


    def download(self,req,resp):
        dir=req.params.get('dir','/')
        file=req.params.get('file','')
        dir=dir.replace('.','')
        filepath='files/'+dir+'/'+file
        if not os.path.isfile(filepath):
            # resp.status=404
            resp.body='(error) file not found'
        else:
            with open(filepath,'rb') as file:
                resp.body=file.read()



        print(req.params)
        pass
    def upload(self,req,resp):
        #
        # print req.params
        # return
        file=req.params['file']
        filename=req.params['filename']
        directory=req.params.get('dir','/')
        directory=directory.replace('.','')
        path='files/'+directory
        path=path.replace('///','/')
        path=path.replace('//','/')
        filename=path+'/'+filename
        if not os.path.isdir(path):
            os.mkdir(path)
        if not os.path.exists(filename):
            if isinstance(file,str):
                open(filename,'wb').write(file)
            else:
                open(filename,'wb').write(file.file.read())
            return 'success'
        else:
            return 'file exists'

    def delfile(self,req,resp):
        params=self._params(req.params['param'])
        filename=''
        key='meizu.com'
        directory='/'
        k=''
        if  'f' in params:
            filename=params['f']
        else:
            return '-f(filename) require'
        if  'k' in params:
            k=params['k']
        else:
            return '-k(key) require'
        if  'd' in params:
            directory=params['d']
        if not key==k:
            return 'key error'
        directory=directory.replace('.','')
        path='files/'+directory + '/' +filename
        if os.path.exists(path):
            os.remove(path)
            return "sucess"
        else:
            return "Not Found"
    def rexec(self,req,resp):
        params=self._params(req.params['param'])
        ip=''
        cmd=''
        k=''
        key='Mz'
        user='root'
        password='root'
        port=22
        if 'i' in params:
            ip=params['i']
        else:
            return '-i(ip) require'
        if 'c' in params:
            cmd=params['c']
        else:
            return '-c(command) require'
        if  'k' in params:
            k=params['k']
        else:
            return '-k(key) require'
        if not key==k:
            return 'key error'
        if  'u' in params:
            user=params['u']
        if  'p' in params:
            password=params['p']
        if  'P' in params:
            port=params['P']
        return self._remote_exec(ip,cmd, user= user, password=password,port=port)

    def _remote_exec(self,ip,cmd,user='root',password='root',port=22,key_file=''):
        try:
            import paramiko
            ssh=paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            if key_file!='':
                pkey= paramiko.RSAKey.from_private_key_file (key_file,password)
                try:
                      ssh.connect(ip,port=port,username=user,password=password,pkey=pkey)
                except Exception as err:
                      self.app.logger.error("PKERROR:"+str(err))
            else:
                ssh.connect(ip,port,user,password)
            ssh.exec_command('sudo -i',get_pty=True)
            ret=[]
            reterr=[]
            if isinstance(cmd,list):
               for c in cmd:
                   stdin, stdout, stderr = ssh.exec_command(cmd,get_pty=True)
                   reterr.append("".join(stderr.readlines()))
                   ret.append("".join(stdout.readlines()))
            else:
               stdin, stdout, stderr = ssh.exec_command(cmd,get_pty=True)
               reterr=stderr.readlines()
               ret=stdout.readlines()

            if len(reterr)>0:
                return "".join(reterr)
            else:
                return "".join(ret)
        except Exception as er:
            self.app.logger.error(er)
            return str(er)
        finally:
            try:
                ssh.close()
            except Exception as err:
                pass

################################################env###############################################
    def _checkenv(self,param):
        params=self._params(param)
        key=''
        group='default'
        if 'g' in params:
            group=params['g']
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        rows=ci.db.query("select * from env where `group_`='%s' and `key_`='%s'"% (group,key))
        if len(rows)>0:
            return True
        else:
            return False
    def listenvgroup(self,req,resp):
        params=self._params(req.params['param'])
        sql="select group_ from env group by group_"
        rows=ci.db.query(sql)
        ret=''
        for row in rows:
            if row['group_']!=None:
                ret+=str(row['group_'])+"\n"
        return ret

        return ret
    def listenv(self,req,resp):
        params=self._params(req.params['param'])
        group='default'
        export='0'
        if 'g' in params:
            group=params['g']
        if 'e' in params:
            export=params['e']
        sql="select key_,value_ from env where `group_`='%s'" % (group)
        rows=ci.db.query(sql)
        if len(rows)==0:
            return '(error) not found'
        ret=''
        for row in rows:
            if export=='1':
                ret+='export '+row['key_']+'='+row['value_']+"\n"
            else:
                ret+=row['key_']+'='+row['value_']+"\n"

        return ret
    def updateenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        value=''
        group='default'
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if 'g' in params:
            group=params['g']
        if 'v' in params:
            value=params['v']
        else:
            return '-v(value) require'
        if not self._checkenv(req.params['param']):
            return '(error)key not is exsit'
        ci.db.update('env',{'value_':value},{'key_':key,'group_':group})
        return 'ok'

    def addenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        value=''

        group='default'
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if 'g' in params:
            group=params['g']
        if 'v' in params:
            value=params['v']
        else:
            return '-v(value) require'
        if self._checkenv(req.params['param']):
            return '(error)key is exsit'
        ci.db.insert('env',{'key_':key,'value_':value,'group_':group})
        return 'ok'
    def delenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        group='default'
        if 'g' in params:
            group=params['g']
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if self._checkenv(req.params['param']):
            ci.db.delete('env',{'key_':key,'group_':group})
            return 'ok'
        else:
            return '(error)key no found'
    def getenv(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        group='default'
        if 'g' in params:
            group=params['g']
        if 'k' in params:
            key=params['k']
        else:
            return '-k(key) require'
        if not self._checkenv(req.params['param']):
            return '(error)key no found'
        return ci.db.scalar("select value_ from env where `group_`='%s' and `key_`='%s'"% (group,key))['value_']

################################################ doc ###############################################
    def _checkdoc(self,param):
        params=self._params(param)
        id=''
        if 'k' in params:
            id=params['k']
        else:
            return '-k(key) require'
        rows=ci.db.query("select * from doc where `id`='%s'"% (id))
        if len(rows)>0:
            return True
        else:
            return False
    def listdoc(self,req,resp):
        params=self._params(req.params['param'])
        if 'k' in params:
            return self.getdoc(req.params['param'])
        sql="select cmd from doc group by cmd"
        rows=ci.db.query(sql)
        ret=''
        for row in rows:
            if row['cmd']!=None:
                ret+=(row['cmd'].encode('utf-8'))+"\n"
        return ret


    def adddoc(self,req,resp):
        params=self._params(req.params['param'])
        cmd=''
        doc=''
        remark=''
        if 'c' in params:
            cmd=params['c']
        if 'd' in params:
            doc=params['d']
            if cmd=='':
                cmd=doc.strip().split(" ")[0]
        else:
            return '-d(document) require'
        if 'r' in params:
            remark=params['r']
        sql='''INSERT INTO doc
            (
            cmd,
            doc,
            remark
            )
            VALUES
            (
            '{cmd}',
            '{doc}',
            '{remark}'
            )'''
        ci.db.query(sql,{'cmd':cmd,'doc':doc,'remark':remark})
        #ci.db.insert('doc',{'cmd':cmd,'doc':doc,'remark':remark})
        return 'ok'
    def deldoc(self,req,resp):
        params=self._params(req.params['param'])
        id=''
        if 'k' in params:
            id=params['k']
        else:
            return '-k(id) require'
        if self._checkdoc(req.params['param']):
            ci.db.delete('doc',{'id':id})
            return 'ok'
        else:
            return '(error)key no found'
    def getdoc(self,req,resp):
        params=self._params(req.params['param'])
        key=''
        if 'k' in params:
            key=params['k']
        else:
            return '-k(keyword) require'
        if 'a' in params:
            rows= ci.db.query("select id,doc from doc where  `cmd` like '%%%s%%' or doc like '%%%s%%'"% (key,key))
        else:
            rows= ci.db.query("select id,doc from doc where  `cmd`='%s'"% (key))
        ret=''
        outid='i' in params
        for row in rows:
            if row['doc']!=None:
                if outid:
                    ret+='# docid:  '+str(row['id'])+"\n"+(row['doc'].encode('utf-8'))+"\n"*3
                else:
                    ret+=str(unicode.encode(row['doc'],'utf-8','ignore'))+"\n"*3
                #ret+="#"*50+"\n"
        return ret

################################################ tags ###############################################
    def addtag(self,req,resp):
        params=self._params(req.params['param'])
        table=''
        tag=''
        if 'tag' in params:
            tag=params['tag']
        else:
            return '--tag(tag) require'
        if 'object' in params:
            table=params['object']
        else:
            return '--object(object name) require'
        if tag.find('=')==-1:
            return 'tag must be "key=value"'
        body={}
        for t in tag.split(';'):
            kv=t.split('=')
            if len(kv)==2:
                body[kv[0]]=kv[1]
        row=ci.db.scalar("select id,body from tags where tbname='{tbname}' limit 1 offset 0",{'tbname':table})
        if row==None:
            data={'tbname':table, 'body':json.dumps(body)}
            ci.db.query("insert into tags(tbname,body) values('{tbname}','{body}')",data)
        else:
            old=json.loads(row['body'])
            for k in body.keys():
                old[k]=body[k]
            data={'body':json.dumps(old),'id':row['id']}
            ci.db.query("update tags set body='{body}' where id='{id}'",data)
        return 'success'

    def listtag(self,req,resp):
        params=self._params(req.params['param'])
        rows=ci.db.query("select tbname,body from tags")
        # return rows
        s=set()
        for row in rows:
            tags=json.loads(row['body'])
            for k in tags.keys():
                s.add('object_name: '+row['tbname'].encode('utf-8')+"\ttags: "+ k.encode('utf-8')+"=%s"% tags[k].encode('utf-8') )
        return "\n".join(s)


    def _check_body_val(self,table,key,value):
        row=ci.db.scalar("select body from tags where tbname='%s' limit 1 offset 0"%table)
        body={}
        if row!=None:
            body=json.loads(row['body'])
        else:
            return True,'OK'
        if key in body.keys():
            if body[key]!='':
                if value in body[key].split(','):
                    return  True,'OK'
                else:
                    return  False," value:'%s' must be in %s" %(key,str(body[key].encode('utf-8').split(',')))
            else:
                return True,'OK'
        else:
            return False," tag name must be in %s" %(str([ k.encode('utf-8') for k in body.keys()]))


################################################ hosts ###############################################

    def addhosttag(self,req,resp):
        params=self._params(req.params['param'])
        tag=''
        ip=''
        if 't' in params:
            tag=params['t']
        else:
            return '-t(tag) require'
        if tag.find('=')==-1:
            return 'tag must be "key=value"'
        if 'i' in params:
            ip=params['i']
        else:
            return '-i(ip) require'
        body={}
        for t in tag.split(';'):
            kv=t.split('=')
            if len(kv)==2:
                ok,messege=self._check_body_val('hosts',kv[0],kv[1])
                if not ok:
                    return messege.encode('utf-8')
                body[kv[0]]=kv[1]

        row=ci.db.scalar("select id,body from hosts where ip='{ip}' limit 1 offset 0",{'ip':ip})
        if row==None:
            data={'ip':ip,'body':json.dumps(body)}
            ci.db.query("insert into hosts(ip,body) values('{ip}','{body}')",data)
        else:
            old=json.loads(row['body'])
            for k in body.keys():
                old[k]=body[k]
            data={'ip':ip,'body':json.dumps(old),'id':row['id']}
            ci.db.query("update hosts set ip='{ip}',body='{body}' where id='{id}'",data)
        return 'success'
    # @cache.Cache(ttl=300)
    def gethost(self,req,resp):
        params=self._params(req.params['param'])
        if 't' not in params:
            return '-t(tag) require'
        rows=ci.db.query("select ip,body from hosts")
        # rows=self._cache_table('hosts')
        ret=[]
        tag=params['t']
        start=time.time()
        rows= self._search_body('hosts',tag)
        print(time.time()-start)
        for row in rows:
                # ret.append(row['ip'])
                ret.append(row['app'])
        return "\n".join(ret)

    def viewhost(self,req,resp):
        params=self._params(req.params['param'])
        if 'i' not in params:
            return '-i(ip) require'
        else:
            ip=params['i']
        data={'ip':ip}
        row=ci.db.scalar("select ip,body from hosts where ip='{ip}' limit 1 offset 0",data)
        return row['body']
    # @cache.Cache(ttl=3600)
    def listhosttag(self,req,resp):
        params=self._params(req.params['param'])
        rows=ci.db.query("select body from hosts")
        # return rows
        s=set()
        for row in rows:
            tags=json.loads(row['body'])
            for k in tags.keys():
                s.add(k.encode('utf-8')+"=%s"% tags[k].encode('utf-8') )
        return "\n".join(s)


    def _search_body(self,table='', exp=''):
        rows=ci.db.query("select * from %s"%table)
        ret=[]
        rows=map(lambda row: json.loads( row['body']) ,rows)
        dutil=ci.loader.helper('DictUtil')
        return  dutil.query( rows,select="name", where=exp)


# ################################################ objs ###############################################
    def addobjs(self,req,resp):
            params=self._params(req.params['param'])
            tag=''
            ip=''
            otype='hosts'
            key=''
            if 't' in params:
                tag=params['t']
            else:
                return '-t(tag) require'
            if tag.find('=')==-1:
                return 'tag must be "key=value"'
            if 'i' in params:
                ip=params['i']
            else:
                return '-i(ip) require'
            if 'o' in params:
                otype=params['o']
            else:
                return '-o(object type) require'
            if 'k' in params:
                key=params['k']
            else:
                key=ip
            body={}
            for t in tag.split(';'):
                kv=t.split('=')
                if len(kv)==2:
                    ok,messege=self._check_body_val(otype,kv[0],kv[1])
                    if not ok:
                        return messege.encode('utf-8')
                    body[kv[0]]=kv[1]

            row=ci.db.scalar("select id,body from objs where `key`='{key}' and otype='{otype}' limit 1 offset 0",{'key':key,'otype':otype})
            if row==None:
                body['_key']=key
                body['_otype']=otype
                data={'ip':ip,'body':json.dumps(body),'otype':otype,'key':key}
                ci.db.query("insert into objs(ip,body,otype,`key`) values('{ip}','{body}','{otype}','{key}')",data)
            else:
                old=json.loads(row['body'])
                for k in body.keys():
                    old[k]=body[k]
                data={'ip':ip,'body':json.dumps(old),'id':row['id']}
                ci.db.query("update objs set ip='{ip}',body='{body}' where id='{id}'",data)
            return 'success'

    def getobjs(self,req,resp):
        params=self._params(req.params['param'])
        otype=''
        tag=''
        cols='*'
        if 't' not in params:
            return '-t(tag) require'
        else:
            tag= params['t']
        if 'o' not in params:
            return '-o(object type) require'
        else:
            otype=params['o']
        if 'c'  in params:
            cols= params['c']
        rows=ci.db.query("select * from objs where otype='{otype}'",{'otype':otype})
        rows=map(lambda row:json.loads(row['body']),rows)
        # print(rows)
        return ci.loader.helper('DictUtil').query(rows,select=cols,where=tag)

# ################################################ cron ###############################################

    def _cmdline_args(self,s):
        import re
        l= re.findall(r"'[\s\S]*[\']?'|\"[\s\S]*[\"]?\"",s,re.IGNORECASE|re.MULTILINE)
        for i,v in enumerate(l):
            s=s.replace(v,'{'+str(i)+'}')
        p=re.split(r'\s+',s)
        ret=[]
        for a in p:
            if re.match(r'\{\d+\}',a):
                a=l[int(re.sub(r'^{|}$','',a))]
            ret.append(a)
        return ret


    def _check_uuid(self,req):
        params=self._params(req.params['param'])
        uuid=''
        if 'i' in params:
            uuid=params['i']
        else:
            return False,'-i(ip or uuid) is required'
        obj=self.hb.get_product_uuid(uuid)
        if len(obj)==1:
            return True,obj[0]['uuid']
        else:
            return False,'client not online'



    def listcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            return self._cron(uuid,action='get')
        return uuid


    def statuscron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            return self._cron(uuid,action='status')
        return uuid

    def stopcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            return self._cron(uuid,action='stop')
        return uuid
    def startcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            return self._cron(uuid,action='start')
        return uuid

    def loadcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            return self._cron(uuid,action='load')
        return uuid

    def addcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            params=self._params(req.params['param'])
            timer='* * * * *'
            args=[]
            cmd=''
            comment=''
            start=''
            out='/tmp/'+ci.uuid()+'.log'
            if not 't' in params:
                return '-t(timer) is required'
            if not 'c' in params:
                return '-c(cmd) is required'
            if 'a' in params:
                args=self._cmdline_args(params['a'])
            if 'o' in params:
                out=params['o']
            cmd=params['c']
            # timer=params['t']
            timer=timer.strip()
            cmd=cmd.strip()
            out=out.strip()
            job={'args':args,'start':'','cmd':cmd,'time':timer,'out':out}
            import urllib
            return self._cron(uuid,action='set?j=%s' % (  urllib.quote(json.dumps(job))) )
        return uuid

    def delcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            params=self._params(req.params['param'])
            if not 'k' in params.keys():
                return '-k(key) is required'
            k=params['k']
            return self._cron(uuid,action='del?h=%s'%k)
        return uuid

    def logcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            params=self._params(req.params['param'])
            if not 'd' in params.keys():
                return '-d(day) is required,for example: 20160607'
            d=params['d']
            return self._cron(uuid,action='log?d=%s'%d)
        return uuid


    def installcron(self,req,resp):
        ok,uuid=self._check_uuid(req)
        if ok :
            return self._cmd(uuid,'sudo cli download -f croncli -o /bin/croncli && sudo chmod +x /bin/croncli && sudo  /bin/croncli install && sudo  /bin/croncli start')
        return uuid

    def _cron(self,uuid,action='get',param=''):
        return self._cmd(uuid, "cli request --url '%s'" % ('http://127.0.0.1:4444/%s'% action) )

    def log(self,req,resp):
        print(req.params)
        pass


