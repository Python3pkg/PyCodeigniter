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
        self.data=[]# {'uuid','status','utime','salt','ips','hostname','system_os'}
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


    def _status_line(self,status='offline'):
        self.check_status()
        result=[]
        for d in self.data:
            if d['status']==status:
                d['utime']=  time.strftime( '%Y-%m-%d %H:%M:%S',time.localtime(d['utime']))
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
        if 'status'  in params.keys():
            status=params['status'].strip()

        if 'uuid' not in params.keys() and  len(params['uuid'])<32:
            self.remove(params['uuid'])
            return '(error) invalid request'
        if 'hostname' in params.keys():
            hostname=params['hostname']

        objs=self.get_product_uuid(params['uuid'])
        # self.uuids.add(params['uuid'])
        ci.redis.sadd('uuids',params['uuid'])

        salt= str(ci.uuid())
        utime=int(time.time())

        if objs==None or len(objs)==0:
            param={'uuid':params['uuid'],'salt':salt,'ips':params['ips'],'utime':utime,'status':'online','status_os':status,'hostname':hostname}
            # self.data.append(param)
            ci.redis.set(params['uuid'],json.dumps(param))
            self.ip2uuid( param)
        elif len(objs)==1:
            if 'salt' in objs[0].keys():
                salt=objs[0]['salt']
            param={'uuid':params['uuid'],'salt':salt,'ips':params['ips'],'utime':utime,'status':'online','status_os':status,'hostname':hostname}
            self.ip2uuid(param)
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
        objs=ci.redis.get(ip)
        if objs!=None:
            ret.append(json.loads(objs))

        if len(ret)>0 or len(ip)>16:
            return ret
        else:
            self.check_status()
            objs=ci.loader.helper('DictUtil').query(self.data,select='*',where="(ips in %s) or (uuid=%s)"% (ip,ip))
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

        self.hb=HeartBeat()

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
         '''
        return h

    def feedback_result(self,req,resp):
        param=req.params['param']
        data=json.loads(param)
        if 'index' in data.keys() and str(data['index']) in ci.redis.smembers("indexs"):
            # self.cmdkeys[str(data['index'])]=data['result']
            ci.redis.setex(str(data['index']),60*5,data['result'])
        ci.logger.info("ip:%s,result:\n%s"%(data['ip'],data['result']))

    def uuid(self,req,resp):
        return ci.uuid()

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
        return self.hb.heartbeat(params)



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
            _ips=row['ips'].split(',')
            for i in _ips:
                if i.startswith('10.'):
                    if self._check_server(i,port):
                        ips.add(i)
                        break
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

            data={'value': json.dumps( {'cmd':cmd.encode('utf-8'),'md5': ci.md5(cmd.encode('utf-8') +str(salt)),'timeout':str(timeout),'user':user}) }
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
            ci.redis.sadd('indexs',index)
            start=time.time()
            if async=='1':
                return index
            if json.loads(ret['node']['value'])['cmd']==cmd:
                while True:
                    if (time.time()-start> timeout) or self.cmdkeys[index]!='':
                        ci.redis.srem('indexs',index)
                        break
                    else:
                        # time.sleep(0.1)
                        # if self.cmdkeys[index]!='':
                        #     ret=self.cmdkeys[index]
                        #     del self.cmdkeys[index]

                        time.sleep(0.5)
                        ret=ci.redis.get(index)
                        if ret!='' and ret!=None:
                            ci.redis.srem('indexs',index)
                            try:
                                return ret.encode('utf-8')
                            except Exception as er:
                                return ret
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


    @auth
    def cmd(self,req,resp):
        client_ip=req.env['REMOTE_ADDR']
        op_user=ci.redis.get('login_'+req.env['HTTP_AUTH_UUID'])
        if not self._is_while_ip(client_ip):
            return '(error) ip is not in white list.'
        params=self._params(req.params['param'])
        cmd=''
        ip=''
        user='root'
        timeout=5
        async='0'
        out='text'
        if  'c' in params:
            cmd=params['c']
        else:
            return '-c(cmd) require'
        if  'i' in params:
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
        if ip.find(',')!=-1:
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
                    tqs.put(ip2uuid[i])
                else:
                    if len(i)==36:
                        tqs.put(i)
                    else:
                        failsip.append(i)
                # result[i]=self._cmd(i,cmd,timeout=timeout,user=user,async=async)
            threads = [gevent.spawn(task,tqs) for i in xrange(50)]
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


    @auth
    def cmd2(self,req,resp):
        client_ip=req.env['REMOTE_ADDR']
        op_user=ci.redis.get('login_'+req.env['HTTP_AUTH_UUID'])
        if not self._is_while_ip(client_ip):
            return '(error) ip is not in white list.'
        params=self._params(req.params['param'])
        cmd=''
        ip=''
        user='root'
        timeout=5
        async='0'
        out='text'
        if  'c' in params:
            cmd=params['c']
        else:
            return '-c(cmd) require'
        if  'i' in params:
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
        if ip.find(',')!=-1:
            import gevent
            import gevent.queue
            tqs= gevent.queue.Queue()
            ips=ip.split(',')

            _uuids= filter(lambda x:len(x)==36,ips)
            for i in _uuids:
                uuid2ip[str(i)]=str(i)
            map(lambda x:tqs.put(str(x)),_uuids)
            _ips= filter(lambda x:len(x)!=36,ips)
            p=ci.redis.pipeline()
            if len(_ips)>0:
                for i in _ips:
                    p.smembers(i)
                lset=p.execute()
                for i,v in enumerate(_ips):
                    if len(lset[i])>0:
                        _uuid= str(lset[i].pop())
                        ip2uuid[str(v)]=_uuid
                        tqs.put(_uuid)
                    else:
                        failsip.append(str(v))

            threads = [gevent.spawn(task,tqs) for i in xrange(50)]
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

    # def shell(self,file='',param='',dir='shell'):
    #     dir=dir.replace('..','').replace('.','').replace('/','')
    #     path= 'files'+ os.path.sep+ dir+ os.path.sep + file
    #     if os.path.isfile(path):
    #         return open(path,'rb').read()
    #     else:
    #         return "#!/bin/bash\n echo '(error) file not found'"

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

    @cache.Cache(ttl=3600,key="#p[0]",md5=False)
    def _cache_table(self,table):
        print('xxxxxx')
        return ci.db.query("select * from %s" % table)


    def aaa(self,req,resp):
        print ci.loader.helper('DictUtil')
        rows=ci.db.query('select * from hosts')
        print rows
        #return ci.loader.helper('DictUtil').query(rows,'select aa,bb,ip where ip like 172.17.140.133')
        return ci.loader.helper('DictUtil').query({"xx":"x"},"select aa,bb,ip where ip like '' ")

    def abc(self,req,resp):
        return u'你好'
        s=time.time()
        for i in xrange(1,100000):
            self._cache_table('hosts')[0]
        print(time.time()-s)
        return 'abc'


    def test2(self,req,resp):
        # pass
        print ci.db.query("select * from objs where ip='{ip}'",{'ip':'172.17.140.133'})




    def test3(self,req,resp):
        rows=self._cache_table('hosts')
        for index,row in enumerate(rows):
            r=json.loads(row['body'])

            rows[index]=r
        # import pymongo
        #
        # conn = pymongo.MongoClient("127.0.0.1",27017)
        # db = conn.test
        # for row in rows:
        #
        #     db.test.insert_one(row)



    def test(self,req,resp):

        # from data_query_engine import DataQueryEngine

        rows=self._cache_table('hosts')
        # rows=self.db.query('select * from hosts limit 10')
        # rows=self.db.query('select * from hosts ')
        start=time.time()
        data=[]

        for index,row in enumerate(rows):
            r=json.loads(row['body'])

            rows[index]=r


        # print(rows)
        # query = DataQueryEngine(rows, "select * from ")
        # return  query.get_results()




        # query = Sql4Json(json.dumps({"data":rows}), "select ip,business from / where room_en_short=='GZ-NS'")
        # query = Sql4Json(json.dumps({"data":rows}), "select * from data")
        # query = Sql4Json(json.dumps(rows), "select ip,business from / where  module > 'sync-web'")


        # query = DataQueryEngine(rows, "select * from  /  where  module == 'sync-web'")
        # return  query.get_results()
        #
        # print time.time()-start
        # results_dictionary = query.get_results()
        # return results_dictionary







    def _search_body(self,table='', exp=''):
        # assert  table!=''
        # exp=exp.replace('&&',' and ')
        # exp=exp.replace('||',' or ')
        # rows=ci.db.query("select * from %s"%table)
        # ret=[]
        # def tmp(a):
        #     return ('('+(a.group(0)).encode("utf-8").replace("'",'')+')').decode('utf-8')
        # exp=re.sub(r'(\w+\s*(=|like)\s*[\'](?:[^\']+)[\'])|(\w+(=|like)\s*(?:[^\s]+)\s*)',tmp,exp)
        # print(exp)
        # s=time.time()
        rows=ci.db.query("select * from %s"%table)

        ret=[]

        # for row in rows:
        #     row['ip']=row['ip']



        rows=map(lambda row: json.loads( row['body']) ,rows)


        dutil=ci.loader.helper('DictUtil')

        print(rows)



        return  dutil.query( rows,select="name", where=exp)


        # expmatch= dutil.query( rows, exp)
        #
        # print len(rows)
        #
        #
        # ret = filter(lambda row: expmatch.calc(data_dict=json.loads( row['body'])), rows)
        # print("xxxxxxxxxxxxxx:"+str(time.time()-s))
        # return ret

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


