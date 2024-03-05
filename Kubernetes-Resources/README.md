# Snyk-Kubernetes-reconciler
Stop-gap visibility while V3 of the enterprise monitor is not GA

# Disclaimers 

1. This will work with Dockerfiles
2.  If you are looking to do cadenced runs you can easily convert this to a cronjob (https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)

# How to Deploy

To deploy the K8s reconciler, you will first need to create the relevant Role resources; within the K8s folder, there is a file roleResources.yaml which contains: A serviceAccount, ClusterRole, ClusterRoleBinding. The serviceAccount gets mounted into the pod and the cluster scope is needed to grab all pods, to deploy you need to run `kubectl apply -f roleResources.yaml`. If there is an issue deploying this file, you can apply them individually as well.

Once the Resources are created you will need to create a secret named `snyk-creds` in the namespace your job runs. The following command can be used to generate the secret, there is no need to include the `Token` prefix for your APITOKEN:
```
kubectl create secret generic snyk-creds \                       
        --from-literal=DOCKERUSERNAME=myUsername \
        --from-literal=DOCKERPASSWORD=myPassword \
        --from-literal=ORGID=mySnykOrg \
        --from-literal=APITOKEN=myToken
```
After creating your secret, you can run a job with `kubectl apply -f job.yaml`. If you are looking to do cadenced runs you can easily convert this to a cronjob (https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/)
