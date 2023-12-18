# Snyk-Kubernetes-reconciler
Stop-gap visibility while V3 of the enterprise monitor is not GA

# Disclaimers 

1. This will work with Dockerfiles
2.  If you are looking to do cadenced runs you can easily convert this to a cronjob (https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

# How to Deploy

To deploy the K8s reconciler, you will first need to create the relevant Role resources; within the K8s folder, there is a file roleResources.yaml which contains: A serviceAccount, ClusterRole, ClusterRoleBinding. 

The serviceAccount gets mounted into the pod and the cluster scope is needed to grab all pods, to deploy you need to run
 `'kubectl apply -f roleResources.yaml'`
 
 If there is an issue deploying this file, you can apply them individually as well.

Once the Resources are created you will need to modify the 'job.yaml' to include your environment variables (This will most likely be changed to a configmap in the future). 

After adding in your vars, you can run a job
` 'kubectl apply -f job.yaml'. `
 

# Troubleshooting

Depending on the CRI you may need to modify both the script and the (cron)job. If you are using containerd you'll have to replace the 'docker tag {}{} with' 'crictl', as well as change the socket mounts in the job YAML file to reflect the underlying CRI. The dockerfile does come with the config for both crictl/docker-cli, one or the other can be removed and this can be rebuilt without the other to trim down on image size.
