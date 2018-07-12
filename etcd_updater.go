package main

import(
	"os"
	"github.com/coreos/etcd/client"
	"io/ioutil"
	"context"
	log "github.com/sirupsen/logrus"
	"flag"
	"gopkg.in/yaml.v2"
	"time"
)

type Data struct {
	Key string `yaml:"key"`
	Type string `yaml:"type"`
	Path string `yaml:"path"`
	Value string `yaml:"value"`
}

type Role struct {
	Name string `yaml:"role"`
	Permissions struct{
		Read []string `yaml:"read"`
		Write []string `yaml:"write"`
		ReadWrite []string `yaml:"readwrite"`	
	} `yaml:"permissions"`
}

type User struct {
	Name string `yaml:"name"`
	Password string `yaml:"password"`
	Roles []Role `yaml:"roles"`
	Disable bool `yaml:"disable"`
}

type Config struct {
	EtcdEndpoint []string `yaml:"etcd_endpoint"`
	Admin map[string]string `yaml:"admin"`
	Users []User `yaml:"users"`
	UserData []*Data `yaml:"data"`
}

func (c *Config) configLoader(configFile string) {
    data, err := ioutil.ReadFile(configFile)
    if err != nil {
    	panic(err.Error())
    }

    err = yaml.Unmarshal(data, c)
    if err != nil {
            panic(err.Error())
    }
}

func permissionChecker(pUser, pEtcd []string) ([]string, []string) {
	var permissionsGiant []string
	var permissionsRevoke []string

	if len(pUser) == 0 {
		return pUser, pEtcd
	}

	for _, pU := range pUser {
		var flag = true
		for _, pE := range pEtcd {
			if pE == pU {
				flag = false
			}
		}

		if flag {
			permissionsGiant = append(permissionsGiant, pU)
		}
	}

	for _, pE := range pEtcd {
		var flag = true
		for _, pU := range pUser {
			if pE == pU {
				flag = false
			}
		}

		if flag {
			permissionsRevoke = append(permissionsRevoke, pE)
		}
	}

	return permissionsGiant, permissionsRevoke
}

func permissionApply(cli client.Client, r *client.Role, roleName, roleType string, roleValue []string) {
	var api client.AuthRoleAPI
	api = client.NewAuthRoleAPI(cli)

	var permissionsGiant []string
	var permissionsRevoke []string
	var permType client.PermissionType

	if roleType == "read" {
		permType = client.ReadPermission
		permissionsGiant, permissionsRevoke = permissionChecker(roleValue, r.Permissions.KV.Read)
	} else if roleType == "write" {
		permType = client.WritePermission
		permissionsGiant, permissionsRevoke = permissionChecker(roleValue, r.Permissions.KV.Write)
	} else if roleType == "readwrite" {
		permType = client.ReadWritePermission
		permissionsGiant, permissionsRevoke = permissionChecker(roleValue, r.Permissions.KV.Read)
	}

	if _, err := api.GrantRoleKV(context.Background(), roleName, permissionsGiant, permType); err != nil {
		detectServerError(err)
		log.Warn(err.Error())
	}

	// Avoid len(readwrite) == 0 ~ read + write slice = 0, and result all permission will be deleted
	if roleType != "readwrite" && len(permissionsRevoke) != 0 {
		if _, err := api.RevokeRoleKV(context.Background(), roleName, permissionsRevoke, permType); err != nil {
			log.Warn(err.Error())
		}		
	}
}

func (c *Config) roleChecker(cli client.Client, role Role, roleNotExist bool) error {
	var api client.AuthRoleAPI
	api = client.NewAuthRoleAPI(cli)

	r, err := api.GetRole(context.Background(), role.Name)
	if err != nil {
		detectServerError(err)
		if err := api.AddRole(context.Background(), role.Name); err != nil {
			detectServerError(err)
			return err
		}
	}

	for {
		if r, err = api.GetRole(context.Background(), role.Name); err == nil {
			break
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
	
	permissionApply(cli, r, role.Name, "read", role.Permissions.Read)
	permissionApply(cli, r, role.Name, "write", role.Permissions.Write)
	permissionApply(cli, r, role.Name, "readwrite", role.Permissions.ReadWrite)

	return nil
}

func (c *Config) userChecker(cli client.Client) {
	var api client.AuthUserAPI
	api = client.NewAuthUserAPI(cli)

	for _, user := range c.Users {
		apiUser, err := api.GetUser(context.Background(), user.Name)

		if err != nil {
			detectServerError(err)
			if err := api.AddUser(context.Background(), user.Name, user.Password); err != nil {
				log.Error(err.Error())
				continue
			}

			apiUser, err = api.GetUser(context.Background(), user.Name)
		}

		if apiUser.Password != user.Password {
			if apiUser, err = api.ChangePassword(context.Background(), user.Name, user.Password); err != nil {
				detectServerError(err)
				log.Error(err.Error())
			}			
		}

		for _, role := range user.Roles {
			var roleNotExist = true
			for _, r := range apiUser.Roles {
				if r == role.Name {
					roleNotExist = false
					break
				}
			}

			if err := c.roleChecker(cli, role, roleNotExist); err != nil {
				log.Info(err.Error())
				detectServerError(err)
				continue
			}

			if roleNotExist {
				if _, err := api.GrantUser(context.Background(), user.Name, []string{role.Name}); err != nil {
					log.Error(err.Error())
					detectServerError(err)
				}							
			}
		}

		if user.Name == "root" {
			var apiAuth client.AuthAPI

			apiAuth = client.NewAuthAPI(cli)
			if err := apiAuth.Enable(context.Background()); err != nil {
				detectServerError(err)
				log.Warn(err.Error())
			}
		}
	}
}

func (d *Data) setKey(k client.KeysAPI, ) {
	if d.Type == "file" {
	    data, err := ioutil.ReadFile(d.Path)
	    if err != nil {
	    	panic(err.Error())
	    }

	    if _, err := k.Set(context.Background(), d.Key, string(data), &client.SetOptions{}); err != nil {
	    	log.Error("Error when set key " + d.Key)
	    	log.Error(err.Error())
	    }
	} else if d.Type == "value" {
	    if _, err := k.Set(context.Background(), d.Key, d.Value, &client.SetOptions{}); err != nil {
	    	log.Error("Error when set key " + d.Key)
	    	log.Error(err.Error())
	    }		
	} else {
		log.Warn("The type " + d.Type + " is not supported.")
	}
}

func detectServerError(err error) {
	if err.Error() == "client: etcd cluster is unavailable or misconfigured" {
		time.Sleep(time.Duration(30) * time.Second)
		panic(err)
	}
}

func main() {
	var configFile string
	var c Config
    flag.StringVar(&configFile, "config", "", "path to config file")
    flag.Parse()

    c.configLoader(configFile)

	var etcd_endpoint = []string{"http://127.0.0.1:2379"}
	if len(c.EtcdEndpoint) != 0 {
		etcd_endpoint = c.EtcdEndpoint
	} else if os.Getenv("etcd_endpoint") != "" {
		etcd_endpoint = []string{os.Getenv("etcd_endpoint")}
	}

	cli, err := client.New(client.Config{
		Endpoints:   etcd_endpoint,
		Transport:   client.DefaultTransport,
		Username: 	 c.Admin["name"],
		Password: 	 c.Admin["password"],
		HeaderTimeoutPerRequest: 50 * time.Second, // Incase Etcd behind proxy, this value must be lesser than proxy timeout
	})

	log.Info(cli)
	if err != nil {
		panic(err)
	}
	
	c.userChecker(cli)

	kAPI := client.NewKeysAPI(cli)

	for _, data := range c.UserData {
		data.setKey(kAPI)
	}
}


// docker run -d --name etcd -p 4001:4001  -p 2379:2379 quay.io/coreos/etcd:v2.3.8 --listen-client-urls=http://0.0.0.0:2379,http://0.0.0.0:4001 --advertise-client-urls=http://0.0.0.0:2379,http://0.0.0.0:4001 --debug --name=etcd0 --initial-cluster=etcd0=http://127.0.0.1:2380 --initial-advertise-peer-urls=http://127.0.0.1:2380