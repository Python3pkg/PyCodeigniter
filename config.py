import logging
db={
    'creator':'sqlite3',
    'database':'cli.db',
    'maxconnections':30,
    'blocking':True,
    'debug':True
}

cmdb={
    'creator':'pymysql',# sqlite3
    'host':'127.0.0.1',
    'user':'root',
    'passwd':'root',
    'database':'cmdb',
    'charset':'utf8',
    'maxconnections':30,
    'blocking':True,
    'autocommit':True,
    'debug':False
}


mail={
    'host':'smtp.163.com',
    'user':'test',
    'password':'123456',
    'postfix':'163.com'
}


server={
    'port':8005,
    'host':'0.0.0.0',
    'envroment':'development',
    'static_dir':'resources',
    'cache_dir':'cache',
    'access_log_dir':'logs'
}


cache={
    'type':'redis',
    'cache_instance':'',
    'max_count':100
}

redis={
    'host':'127.0.0.1',
    'port':6379,
    'db':0,
# 'password':None,
    'max_connections':100
}


autoload={
    'controllers':{
#"Index":"Index",
    },
    'models':{

    },
    'library':{

    },
    'helps':{

    }

}


log={

    'file':r'./log.log',
    'level':logging.INFO,
    'file_size':1024*1024*100,
    'back_count':10

}

white_ips=['127.0.0.1']
web_white_ips=['127.0.0.1']
web_key='5c37e294d9d228035ccd85f0a0e56ebf'
etcd={'server':['http://127.0.0.1:4001/v2/keys'],'prefix':'/keeper'}

domain='zchannel.web.com'

influxdb={
    'host':'127.0.0.1',
    'port':8086,
    'username':'admin',
    'password':'admin',
    'database':'test'
}


repair={
    'key_filename':'',
    'user':'',
    'password':'',
    'port':22,

}

config={
    'log':log,
    'db':db,
    'mail':mail,
    'server':server,
    'cache':cache,
    'autoload':autoload,
    'redis':redis,
    'repair':repair,
    'white_ips':white_ips,
    'web_key':web_key,
    'web_white_ips':web_white_ips,
    'etcd':etcd,
    'cmdb':cmdb,
    'influxdb':influxdb,
    'domain':domain
}
