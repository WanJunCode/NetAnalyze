#include "Log.h"



// 日志等级 对应的 字符串，用于将日志等级转化为字符串
const static char *LogLevelName[Log::NUM_LOG_LEVELS] =
{
    "TRACE ",
    "DEBUG ",
    "INFO  ",
    "WARN  ",
    "ERROR ",
    "FATAL ",
};

Log::Log(){
    log4cpp::PatternLayout* pLayout = new log4cpp::PatternLayout();
    pLayout->setConversionPattern("%d: %p %c %x: %m%n");
    log4cpp::Appender* appender = new log4cpp::FileAppender("FileAppender","test_logcpp4cpp.out");
    appender->setLayout(pLayout);
    log4cpp::Category::getRoot().setAppender(appender);
    // Category 需要设置 priority 优先级
    log4cpp::Category::getRoot().setPriority(log4cpp::Priority::DEBUG);
    out.open(LOG_FILE,std::ios::app);
}

Log::~Log(){
    log4cpp::Category::shutdown();
    out.close();
}

void Log::printf(LogLevel level,unsigned long pthread_id,const std::string filename,int line,const std::string function,const char *cmd,...)
{
    // sync
    // std::unique_lock<std::mutex> lock(mutex_);
    std::lock_guard<std::mutex> lock(mutex_);

    time_t tmptime = time(NULL);//这句返回的只是一个时间戳
    struct tm* ilocaltime= localtime(&tmptime);
    char timeStr[150]={0};
    sprintf(timeStr,"[%lu][%s][%s][%d][%s]:[%02d:%02d:%02d]",pthread_id,LogLevelName[level],filename.c_str(),line,function.c_str(),
        ilocaltime->tm_hour,ilocaltime->tm_min,ilocaltime->tm_sec);

    {
        va_list args;       //定义一个va_list类型的变量，用来储存单个参数
        va_start(args,cmd); //使args指向可变参数的第一个参数
        
        // 打印到文件
        Log::getInstance()<<timeStr<<vform(cmd,args);
        // 打印到控制台
        std::cout<<timeStr<<vform(cmd,args);

        // 打印到log4cpp
        switch (int(level))
        {
        case LogLevel::TRACE:
            log4cpp::Category::getRoot().notice(vform(cmd,args));
            break;
        case LogLevel::DEBUG:
            log4cpp::Category::getRoot().debug(vform(cmd,args));
            break;
        case LogLevel::INFO:
            log4cpp::Category::getRoot().info(vform(cmd,args));
            break;
        case LogLevel::WARN:
            log4cpp::Category::getRoot().warn(vform(cmd,args));
            break;
        case LogLevel::ERROR:
            log4cpp::Category::getRoot().error(vform(cmd,args));
            break;
        case LogLevel::FATAL:
            log4cpp::Category::getRoot().fatal(vform(cmd,args));
            break;
        default:
            log4cpp::Category::getRoot().notice("default\n");
            break;
        }
        va_end(args);       //结束可变参数的获取 
    }
}