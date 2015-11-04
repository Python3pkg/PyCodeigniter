
import logging


db={
    'host':'127.0.0.1',
    'user':'root',
    'passwd':'root',
    'database':'test',
    'charset':'utf8',
    'maxconnections':30,
    'blocking':True,
    'autocommit':True,
    'debug':True
}



log={

    'file':r'./log.log',
    'level':logging.INFO,
    'file_size':1024*1024*100,
    'back_count':10

}


mail={
    'host':'smtp.163.com',
    'user':'abc',
    'password':'abc',
    'postfix':'163.com'
}


server={
    'fastpy':False,
    'port':8005,
    'host':'0.0.0.0',
    'envroment':'development',
    'static_dir':'static',
    'cache_dir':'cache',
    'access_log':'./access.log'
}


cache={
    'type':'memory',
    'cache_instance':'',
    'max_count':100
}


autoload={
    'controllers':{
        "Index":"Index",
    },
    'models':{

    },
    'library':{

    },
    'helps':{

    }

}



cron={
 'threadpool':20,
 'processpool':5,
 'jobs':[
     #{'cron':'*/5 * * * * *','command':'Index._timer','callback':'Index._timer_callback'},
     #{'cron':'*/5 * * * * *','command':'script:top -n 1 -b','callback':'Index._timer_callback'}
 ]
}

zookeeper={
    'url':'',
    'path':'/tmp',
    'user':'',
   'password':'',
   'timeout':10
}

session = {
    'type':'local',## redis|local
    'expire':86400,
    # 'host': "127.0.0.1:6379",
    # 'passwd':""
}

template={
    'path':"./views",
    'engine':'jinja2' # or Tenjin
}

config={

'log':log,
'db':db,
'mail':mail,
'server':server,
'cache':cache,
'autoload':autoload,
# 'template':template
#'session':session
# 'cron':cron,
# 'zookeeper':zookeeper

}


if __name__=='__main__':
    print(config)

