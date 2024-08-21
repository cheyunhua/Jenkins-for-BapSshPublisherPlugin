这是一个批量修改jenkins插件<publish_over_ssh.BapSshHostConfiguration>的ssh server的密码的Python脚本

注意事项1：

   jenkins在高版本需要关闭

    系统管理-》script Console

    在下面脚本命令行中输入
     hudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION = true
     在jenkins主机上一定要创建这个文件    mkdir  /run/secrets    && touch  /run/secrets/PUBLISH_OVER_SSH_KEY


注意事项2：
   

     在jenkins下的/root/.jenkins执行   cat jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml |grep /name | sed 's@<name>@@g' |sed 's@</name>@@g'  复制到test.xlsx的列1


     cat jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml |grep /name | sed 's@<hostname>@@g' |sed 's@</hostname>@@g'   复制到test.xlsx的列2


 注意事项3：
 
      注意jenkins的变量以及pycharm版本为2024.1.4   jenkins版本2.466
 
  





感谢这个脚本是在https://www.modb.pro/db/1785179394042040320基础上改编而成
