import re, sys, pickle, random, os, socket, time
import logging, requests
import paramiko
import yaml, json
from prettytable import PrettyTable
from errbot import BotPlugin, botcmd, re_botcmd, arg_botcmd, botflow, BotFlow, FlowRoot
from slackclient import SlackClient

log      = logging.getLogger("plugins.teleport_production")
hostip   = '999.99.999.999'
admin    = 'root'

class teleportProduction(BotPlugin):
    def activate(self):
         super().activate()
    
    def search_index(self,index,var):
        for index, item in enumerate(index):
          if item == var:
            return index

    def get_ssh_client(self):
        key = paramiko.RSAKey.from_private_key_file(os.getenv("PROD_SSH_KEY"))
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        client.connect(hostip, username=admin, port=22, pkey= key)
        return client

    def execute_command(self, cmd):
        try:
            ssh = self.get_ssh_client()
            log.info(cmd)
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
            output = stdout.readlines()
            ssh.close()
            return output
        except paramiko.SSHException:
            return "connection failed to upstream"
        except paramiko.BadHostKeyException as badHostKeyException:
            return "Unable to verify server's host key: %s" % badHostKeyException
        except socket.error:
            return "Unable to connect, socket error"

    def get_email(self, usrID):
        token = os.environ["SLACK_TOKEN"]
        sc = SlackClient(token)
        resp = sc.api_call("users.info",user=usrID, )
        email = resp['user']['profile']['email']

        return email    

    def get_administrator(self, slackID):
        try:
            with open("data/data_credential.json", "r") as read_file:
                dict_credentials = json.load(read_file)
           
            lead_email = self.get_email(slackID)
            dict_administrator = dict_credentials.get("admin")
            team_administrator = list(dict_administrator["member"][0:])

            if lead_email in team_administrator:
                print(lead_email+" part of admin teams. welcome aboard dude! ")
                return True
            else:
                return False
        except Exception as e:
            print(e)    


    def get_lead_validation(self, slackID):
        try:
           
            with open("data/data_credential.json", "r") as read_file:
                dict_credentials = json.load(read_file)
           
            lead_email = self.get_email(slackID)
            print(slackID+"\n"+lead_email)

            dict_lead = dict_credentials.get("lead")
            team_lead = list(dict_lead["member"][0:])
            
            if lead_email in team_lead:
                print(lead_email+" part of lead teams")
                return True
            else:
                return False

        except Exception as e:
            print(e)    

    def get_my_roles(self, user):
        role = []
        output = self.execute_command("sudo tctl get users/"+user)
        result = [x.strip(' ') for x in output]
        result = [x.strip('\n') for x in result]
        result = [x.strip('- ') for x in result]
        role = list(result[self.search_index(result,"roles:")+1:self.search_index(result,"status:")])
        return role
        
    #tluser_add -e <email> -r <role>
    @arg_botcmd('-e', dest='email',type = str)
    @arg_botcmd('-r', dest='roles',type = str)
    def tluser_add(self, msg, email=None, roles=None):
        user_list = email.split(",")
        administrator = self.get_administrator(msg.extras['slack_event']['user'])
        admin  = self.get_lead_validation(msg.extras['slack_event']['user'])
        len_user = len(user_list)
        
        if admin == True or administrator == True:
            if roles != '':
                # single user add
                if len_user == 1:
                    user = user_list[0]
                    user.replace('@company.com', '')
                    roles = roles.split(",")
                    new_role = []

                    with open("data/data_role.json", "r") as read_file:
                        dict_roles = json.load(read_file)

                    for i in range(len(roles)):
                        if roles[i] in dict_roles:
                           new_role.append(roles[i])
                        else:
                           yield roles[i]+" doesn't exist in role list"

                    if not new_role:              
                        yield "use `!tlrole_search -r rolename` for finding the role you want"
                    else:
                        output = self.execute_command("sudo tctl users add "+user+" --email="+email+" --set-roles="+','.join(new_role))
                        if len(output) != 0:
                            yield "User "+user+" has been added \n"+str(output)
                        else:
                            yield """Error on adding user,
                                     could be users has been *added*. please check the email for registration teleport
                                     or check using `tluser profile [user@email]`
                                     please reach #administrator if still have the issue"""
                # bulk user add
                if len_user > 1:
                    with open("data/data_role.json","r") as read_file:
                             dict_roles = json.load(read_file)

                    roles = roles.split(",")         
                    new_role = []

                    for i in range(len(roles)):
                        if roles[i] in dict_roles:
                            new_role.append(roles[i])
                        else:
                            yield roles[i]+" doesn't exist in role list"

                    if not new_role:
                        yield "use `!tlrole_search -r rolename` for finding the role you want"
                    else:
                        for i in range(len(user_list)):
                            user = user_list[i]
                            user = user.replace('@company.com','')
                            output = self.execute_command("sudo tctl users add "+user+" --email="+email+" --set-roles="+','.join(new_role))
                            if len(output) != 0:
                                yield "User "+user+" has been added \n"+str(output)
                            else:
                                yield """Error on adding user,
                                         could be the user has been *added*. please check the email for registration teleport
                                         or check using `tluser profile [user@email]`
                                        please reach #administrator if still have the issue"""
            else:
                yield "Roles must defined cannot empty"     
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

    #tluser_rm --email <email>
    @arg_botcmd('-e', dest ='email', type = str)
    def tluser_rm(self,msg,email=None):
        user = email.replace('@company.com', '')
        admin = self.get_administrator(msg.extras['slack_event']['user'])
        
        if admin == True:
            output = self.execute_command("sudo tctl users rm "+user)
            print(output)
        
            if len(output) != 0:
                yield "User "+user+" has been removed \n"+str(output)
            else:
                yield "Error on removing user, please reach #administrator"
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

    #tluser_update -e <email> -r <roles>
    @arg_botcmd('-e', dest='email',type = str)
    @arg_botcmd('-r', dest='role_list',type = str)
    def tluser_update (self, msg, email=None, role_list=None):
        user_list = email.split(",")
        role_list = role_list.split(",")
        len_user = len(user_list)

        administrator = self.get_administrator(msg.extras['slack_event']['user'])
        admin  = self.get_lead_validation(msg.extras['slack_event']['user'])
        
        if admin == True or administrator == True:
            if role_list != '':
                # single user update 
                if len_user == 1: 
                    user = email.replace('@company.com', '')
                    role = self.get_my_roles(user)
                    yield "existing role: "+','.join(role)
                    yield "new role will update: "+','.join(role_list)
        
                    for i in role_list:
                        role.append(i)   
                    output = self.execute_command("sudo tctl users update "+user+" --set-roles="+','.join(role))
        
                    if len(output) != 0:
                        yield ','.join(output)
                    else:
                        yield "Error on update user, please reach #administrator"
                # bulk user update  
                elif len_user > 1:
                    for i in range(len(user_list)):
                        user = user_list[i]
                        user = user.replace('@company.com', '')
                        role = self.get_my_roles(user)
        
                        for j in role_list:
                            role.append(j)
                        output = self.execute_command("sudo tctl users update "+user+" --set-roles="+','.join(role))
        
                        if len(output) != 0:
                            yield ','.join(output)
                        else:
                            yield "Error on bulk update user, please reach #administrator"
            else:
                yield "Roles must defined, cannot empty" 
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."
    
    #tluser_my --email <my_email>
    @botcmd(split_args_with=str)
    def tluser_profile(self, msg, args):
        user  = args.replace('@company.com', '')
        
        administrator = self.get_administrator(msg.extras['slack_event']['user'])
        admin  = self.get_lead_validation(msg.extras['slack_event']['user'])
        role_list = []
        if admin == True or administrator == True:
            try:
                role_list = self.get_my_roles(user)
            except Exception as e:
                print(e)
                yield "User doesn't exist"
            finally:
                table = PrettyTable()
                table.field_names = ["name","roles"]
                table.align["roles"] = "l"
                table.add_row([user,'\n'.join(role_list)])
                yield table
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

    #resetuser --email <my_email>
    @botcmd    
    def tluser_reset(self, msg, args):
        email = args

        if "@company.com" in email:
            pass
        else:
            email = args+"@company.com"  

        user = email.replace('@company.com', '')
        administrator = self.get_administrator(msg.extras['slack_event']['user'])
        admin  = self.get_lead_validation(msg.extras['slack_event']['user'])
        role_list = []

        if admin == True or administrator == True:
            role_list = self.get_my_roles(user)

            output = self.execute_command("sudo tctl users rm "+user)
            print(output)

            output = self.execute_command("sudo tctl users add  "+user+" --email="+email+" --set-roles="+','.join(role_list))
            print(output)

            if len(output) != 0:
               yield "user "+user+" has been reset"
               yield output
            else:
               yield "Error on removing user, please reach #administrator"
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."
    
    @arg_botcmd('-e', dest='email',type = str)
    @arg_botcmd('-r', dest='role_list',type = str)
    def tluser_rmrole (self, msg, email=None, role_list=None):
        user  = email.replace('@company.com', '')
        admin = self.get_administrator(msg.extras['slack_event']['user'])
        role_list = []
        if admin == True:
            if role_list != '':
                existing_role = self.get_my_roles(user)
                role_list     = role_list.split(",")

                for i in range(len(role_list)):
                  for index, item in enumerate(existing_role):
                    if item == role_list[i]: 
                       existing_role.pop(index)

                print(existing_role)   
                output = self.execute_command("sudo tctl users update "+user+" --set-roles="+','.join(existing_role))

                if len(output) != 0:
                    yield ','.join(output)
                else:
                    yield "Error on remove user role, please reach #administrator"
            else:
                yield "Roles must defined cannot empyt" 
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

# role commands
    @botcmd
    def tlrole_reload(self, msg, args):
        alpha = self.get_administrator(msg.extras['slack_event']['user'])
        admin = self.get_lead_validation(msg.extras['slack_event']['user'])
        
        if admin == True or alpha == True:
            dict_role = {}
            try:
                output = self.execute_command("sudo tctl roles ls")
                del output[0:2] #removing field labels and ------ 

                parse_role_list = []
                for i in range(len(output)):
                    parse_role_list.append(re.sub(r'\s+', ',', output[i]))
            
                parse_role_dict = []
                for i in range(len(parse_role_list)):
                    parse_role_dict.append(parse_role_list[i].split(','))

                    key   = parse_role_dict[i][0]
                    role  = parse_role_dict[i][0]
                    user  = parse_role_dict[i][1]
                    label = parse_role_dict[i][2:]

                    dict_role[key] = key 
                    dict_role[key] = {
                        "role": role,
                        "user": user,
                        "label":  label
                        }
            finally:
                with open("data/data_role.json", "w") as write_file:
                    json.dump(dict_role, write_file)
                yield str(len(output))+" register"
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

    @botcmd(split_args_with=str)
    def tlrole_add(self, msg,*args):
        
        admin = self.get_administrator(msg.extras['slack_event']['user'])
        if admin == True:
            try:
                 role = ' '.join(args)

                 if role.find("env:") and role.find("app:") == -1:
                     yield "Wrong format for add new role"
                     yield "tlrole add [rolename] [root:readonly] \"[env:envname] [app:appname] \""
                 else:
                     new_role   = role.split(' ')
                     role_label = (',').join(new_role[2:])
                     role_label = role_label.replace(',',' ')

                     role_name       = new_role[0]
                     role_permission = new_role[1]
                     output = self.execute_command("sudo tctl roles add "+role_name+" "+role_permission+" \""+role_label+"\"")
                     print(output)

                     if len(output) != 0:
                         yield "new role has been added "+role_name
                         self.tlrole_reload
            except Exception as e:
                 print(e)
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."         
    
    @arg_botcmd('-r', dest ='name', type = str)
    @arg_botcmd('-t', dest ='tag', type = str)
    def tlrole_update(self, msg, name=None, tag=None):
        role_name = name
        role_tag  = tag

        admin = self.get_administrator(msg.extras['slack_event']['user'])
        if admin == True:
            try:
                with open("data/data_role.json") as read_file:
                    dict_roles = json.load(read_file)

                role_update = dict_roles.get(role_name)
                env_list    = role_update["label"][0:]

                if "env:production" in env_list:
                    index_env = env_list.index("env:production")
                    app_list  = role_update["label"][0:index_env-1] 
                    app_list  = (',').join(app_list).replace("app:","")
                else:
                    index_env = 1
                    app_list  = dict_role["label"][0].replace("app:","") 

                env_list  = role_update["label"][index_env]

                app_new   = list(role_tag.split(','))
                app_new.append(app_list)

                output = self.execute_command("sudo tctl roles update "+role_name+" --set-node-labels=\"app:"+(",").join(app_new)+" "+env_list+"\"")
                print(output)

                if len(output) != 0:
                    yield "role "+role_name+" has been updated with: "+(",").join(app_new)
                    self.tlrole_reload

            except Exception as e:
                print(e)
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."
            

    @botcmd(split_args_with=str)    
    def tlrole_search(self, msg, args):
        role = args
        try:
            with open("data/data_role.json", "r") as read_file:
                dict_roles = json.load(read_file)

            table = PrettyTable()
            table.field_names   = ["user","app","env","ip","role"]
            table.align["user"] = "l"
            table.align["app"]  = "l"
            table.align["ip"]   = "r"
            table.align["role"] = "r"

            for key in dict_roles.keys():
                if args in key:

                    dict_role = dict_roles.get(key)
                    env_list  = dict_role["label"][0:]

                    if "env:production" in env_list:
                        index_env = env_list.index("env:production")
                        app_list  = dict_role["label"][0:index_env-1] 
                        app_list  = ('\n').join(app_list).replace("app:","")

                    if "env:staging" in env_list:
                        index_env = env_list.index("env:staging")
                        app_list  = dict_role["label"][0:index_env-1]
                        app_list  = ('\n').join(app_list).replace("app:","")

                    else:
                        index_env = 1
                        app_list  = dict_role["label"][0].replace("app:","") 

                    app_ip = list(dict_role["label"][2:])
                    if len(app_ip) == 1:
                        app_ip[0]="None"

                    env_list  = dict_role["label"][index_env]
                        
                    table.add_row([
                        dict_role["user"],
                        app_list,
                        env_list.replace("env:",""),
                        '\n'.join(app_ip).replace("ip:",""),
                        dict_role["role"],
                        ])
            yield table
        except Exception as e:
            print(e)

    @botcmd(split_args_with=str)    
    def tlrole_search_ip(self, msg, args):
        try:
            with open("data/data_role.json", "r") as read_file:
                dict_roles = json.load(read_file)

            table = PrettyTable()
            table.field_names   = ["user","app","env","ip","role"]
            table.align["user"] = "l"
            table.align["app"]  = "l"
            table.align["ip"]   = "r"
            table.align["role"] = "r"

            for key, value in dict_roles.items():
                if args in value["label"]:
                    
                    dict_role = dict_roles.get(key)
                    env_list  = dict_role["label"][0:]

                    if "env:production" in env_list:
                        index_env = env_list.index("env:production")
                        app_list  = dict_role["label"][0:index_env-1] 
                        app_list  = ('\n').join(app_list).replace("app:","")

                    if "env:staging" in env_list:
                        index_env = env_list.index("env:staging")
                        app_list  = dict_role["label"][0:index_env-1]
                        app_list  = ('\n').join(app_list).replace("app:","")

                    else:
                        index_env = 1
                        app_list  = dict_role["label"][0].replace("app:","") 

                    app_ip = list(dict_role["label"][2:])
                    if len(app_ip) == 1:
                        app_ip[0]="None"

                    env_list  = dict_role["label"][index_env]
                        
                    table.add_row([
                        dict_role["user"],
                        app_list,
                        env_list.replace("env:",""),
                        '\n'.join(app_ip).replace("ip:",""),
                        dict_role["role"],
                        ])
            yield table
        except Exception as e:
            print(e)                 
               
    @botcmd
    def tlrole_list(self, msg, args):
        admin = self.get_administrator(msg.extras['slack_event']['user'])
        
        if admin == True:
            with open("data/data_role.json", "r") as read_file:
                dict_roles = json.load(read_file)

            try:
                table = PrettyTable()
                table.field_names = ["user","role","app","env"]

                dict_role = {}
                for  key, value in dict_roles.items():
                    dict_role = dict_roles.get(key)

                    env_list  = dict_role["label"][0:]
                    index_env = env_list.index("env:production")
                    app_list  = dict_role["label"][0:index_env-1] 
                    env_list  = dict_role["label"][index_env]
                    
                    table.add_row([
                        dict_role["user"],
                        dict_role["role"],
                        ("\n").join(app_list).replace("app:",""),
                        env_list.replace("env:","")
                    ])
                yield table    
            except Exception as e:
                print(e)
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

# node commands
    @botcmd
    def tlnode_list(self, msg, args):
        admin = self.get_administrator(msg.extras['slack_event']['user'])
        
        if admin == True:
            with open("data/data_node.json", "r") as read_file:
                dict_nodes = json.load(read_file)

            try:
                table = PrettyTable()
                table.field_names = ["app","dc","env","hostname","ipaddr"]
                table.align["app"] ="l"
                table.align["ipaddr"] = "r"

                dict_node = {}
                for  key, value in dict_nodes.items():
                    dict_node = dict_nodes.get(key)
                    table.add_row([
                        dict_node["label"][0].replace("app=",""),
                        dict_node["label"][1].replace("datacenter=",""),
                        dict_node["label"][2].replace("env=",""),
                        dict_node["hostname"],
                        dict_node["ipaddr"]
                        ])
                            
                yield table    
            except Exception as e:
                print(e)
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

    @botcmd(split_args_with=str)    
    def tlnode_search(self, msg,args):
        count = 0
        try:
            with open("data/data_node.json", "r") as read_file:
                dict_nodes = json.load(read_file)

            table = PrettyTable()
            table.field_names = ["app","dc","env","hostname","ipaddr"]

            for key in dict_nodes.keys():
                if args in key:
                    dict_node = dict_nodes.get(key)
                    table.add_row([
                        dict_node["label"][0].replace("app=",""),
                        dict_node["label"][1].replace("datacenter=",""),
                        dict_node["label"][2].replace("env=",""),
                        dict_node["hostname"],
                        dict_node["ipaddr"]
                        ])
                    count = count+1
        finally:
            yield table
            yield "there's "+ str(count)+" server "+args

    @botcmd
    def tlnode_reload(self, msg, match):
        administrator = self.get_administrator(msg.extras['slack_event']['user'])
        admin = self.get_lead_validation(msg.extras['slack_event']['user'])
        
        if admin == True or administrator == True:
            yield "take a coffee :coffee:, while we build the node database...."
            dict_role = {}
            try:
                output = self.execute_command("sudo tctl nodes ls")
                del output[0:2] #removing field labels and ------ 

                parse_node_list = []
                for i in range(len(output)):
                    parse_node_list.append(re.sub(r'\s+', ',', output[i]))
                
                parse_node_dict = []
                for i in range(len(parse_node_list)):
                    parse_node_dict.append(parse_node_list[i].split(','))

                    key      = parse_node_dict[i][3].replace("app=","") #labels[app:] as a key
                    hostname = parse_node_dict[i][0]
                    uuid     = parse_node_dict[i][1]
                    ipaddr   = parse_node_dict[i][2]
                    label    = parse_node_dict[i][3:]

                    dict_role[key] = key 
                    dict_role[key] = {
                        "hostname": hostname ,
                        "uuid":     uuid,
                        "ipaddr":   ipaddr,
                        "label":    label
                        }
            finally:
                with open("data/data_node.json", "w") as write_file:
                    json.dump(dict_role, write_file)
                yield str(len(output))+" nodes has been load"
        else:
            yield "Your not authorized for this! kindly reach #administrator for help."

    @re_botcmd(pattern=r"^tlhelp")
    def listcommand(self, msg, match):
        
        info = """
        
        Hi! Welcome, Me (bang malih) will help you to manage Teleport


        :mega: *user commands*

        *tluser_add* = Adding new teleport users with role 
        option: -r role [cannot be empty]
        `!tluser add -e user@email -r role1,role2,role3`
        *tluser_rm* = removing existing teleport user
        option: -e email [cannot be empty] 
        `!tluser rm -e user@email`
        *tluser reset* = reset teleport user password 
        `!tluser reset user@email`
        *tluser update* = update teleport user roles
        option: -e email [cannot be empty], -r roles [cannot be empty] 
        `!tluser update -e user@email -r role1,role2,role3`
        *tluser_rmrole* = remove some role in a user 
        option: -e email [cannot be empty], -r roles [cannot be empty]
        `!tluser rmrole -e <email> -r role1,role2,role3`
        *tluser profile* = display role list of teleport user 
        `!tluser profile user@email`

        :mega: *role command*
       
        *tlrole update* = adding tag app into existing role
        `tlrole update -r rolename -t nodeapp1,nodeapp2,nodeapp3`
        *tlrole add* = create a new role from specific node
        `!tlrole add <name_production> <root:readonly> "<env:stg app:test>" <= based on node tag`
        *tlrole search* = search roles in databases
        `!tlrole search rolename`
        *tlrole search ip* = search roles in databases using ip address
        `!tlrole search <ipaddr> or ip:<ipaddr>`
        *tlrole reload* = update role databases
        `!tlrole reload`
        *tlrole list* = display all role of Teleport 
        `!tlrole list`

        :mega: *nodes command*

        *!tlnode add* = register new node *TBA*
        option: -n node [cannot be empty]
        `!tlnode add -n node`
        *tlnode reload* = update node databases
        `!tlnode reload`
        *tlnode list* = display all node of Teleport 
        `!tlnode list`
        *tlnode search* = search nodes in databases
        `!tlnode search nodename`

        """

        yield info
