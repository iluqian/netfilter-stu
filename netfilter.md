# 注册
````
struct nf_hook_ops {
			struct list_head list; //which is used to keep a linked list of hook

			/* User fills in from here down. */
		//	The nf_hookfn* struct member is the name of the hook function that we define
			nf_hookfn *hook;   
			struct module *owner; 
			u_int8_t pf; //PF_INET for IPv4
			unsigned int hooknum;  //五个hook点之一
			/* Hooks are ordered in ascending priority. */
			int priority; //优先级
};

````
