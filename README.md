这是一个批量修改jenkins插件<publish_over_ssh.BapSshHostConfiguration>的ssh server的密码的Python脚本

注意事项1：

jenkins在高版本需要关闭

 系统管理-》script Console

在下面脚本命令行中输入
hudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION = true

这个脚本是在https://www.modb.pro/db/1785179394042040320基础上改编而成
