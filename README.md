# Snyk-Kubernetes-reconciler
Stop-gap visibility while V3 of the enterprise monitor is not GA


#How to Deploy

To deploy the K8s reconcile, you will first need to create the relevant Role resources; within the K8s folder, there is roleResources.yaml which contains: A serviceAccount, ClusterRole, ClusterRoleBinding. The serviceAccount gets mounted into the pod and the cluster scope is needed to grab all pods, to deploy you need to run 'kubectl apply -f roleResources.yaml'. If there is an issue deploying this file, you can apply them individually as well.
Once the Resources are created you can then run 'kubectl apply -f job.yaml'. This will generate a one-time run of the reconciler, this can easily be modified to be a cronJob if you wish to have cadenced runs.
