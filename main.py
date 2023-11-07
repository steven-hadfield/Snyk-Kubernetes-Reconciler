import requests as reqs
from kubernetes import client, config
import json
import os


#Scan any missing images, 'images' should be a iterable list
#We can modify the arguments of Snyk Container to include tags which can then be used to create project views or import metadata from the pods if needed
def scanMissingImages(images):
    for missingImage in images:
        cmd = '/usr/local/bin/snyk container monitor {} --org=8a6554e2-1bdf-42a5-b21c-01f63d5ae7cd --tags=kubernetes=monitored'.format(missingImage)
        os.system(cmd)

def deleteNonRunningTargets():
    #will need to retry for when snyk UI dies
    containerImageURL = "https://api.snyk.io/rest/orgs/8a6554e2-1bdf-42a5-b21c-01f63d5ae7cd/container_images?version=2023-11-06~beta"
    response = reqs.get(containerImageURL, headers={'Authorization': '{}'.format(APIKEY)})
    containerResponseJSON = response.json()

    allTargetsUrl = "https://api.snyk.io/rest/orgs/8a6554e2-1bdf-42a5-b21c-01f63d5ae7cd/targets?version=2023-11-06~beta"
    response = reqs.get(allTargetsUrl, headers={'Authorization': '{}'.format(APIKEY)})
    targetResponseJSON = response.json()

    for containerImage in containerResponseJSON['data']:
        image = containerImage['attributes']['names'][0]

        #image that is not running on the cluster
        if image not in allRunningPods:

            #TODO: change the split to replace for '_', depending on the workflow it may make more sense to create targets with <image>_<version>
            imageTagStripped = image.split(':')
            imageTagStripped = imageTagStripped[0]
            for target in targetResponseJSON['data']:
                if target['attributes']['displayName'] == imageTagStripped:
                    deleteTargetURL = "https://api.snyk.io/rest/orgs/8a6554e2-1bdf-42a5-b21c-01f63d5ae7cd/targets/{}?version=2023-11-06~beta".format(target['id'])
                    deleteResp = reqs.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                    if deleteResp.status_code == 204:
                        print("succesfully delete targetID {}, based off image {}".format(target['id'], imageTagStripped))
                    else:
                        print("Some issue deleting targetID {}, based off image {}. Response code: {}".format(target['id'], imageTagStripped, deleteResp.status_code))



# Configs can be set in Configuration class directly or using helper utility




#Load Kubeconfig for interacting with the K8s API. Load in K8s api V1 to query pods.
#config.load_incluster_config() #this loads in cluster config, use when deploying pods to k8s
config.load_kube_config() #local environment
v1 = client.CoreV1Api()


allRunningPods = []
needsToBeScanned = []


for pod in v1.list_pod_for_all_namespaces().items:
    
    for container in pod.spec.containers: 
        image= container.image
        allRunningPods.append(container.image)

        #will need to add some retry logic incase the connection dies
        URL = "https://api.snyk.io/rest/orgs/8a6554e2-1bdf-42a5-b21c-01f63d5ae7cd/container_images?names="+ image + "&version=2023-11-06~beta"
        response = reqs.get(URL, headers={'Authorization': '{}'.format(APIKEY)})
        responseJSON = response.json()

        #print(responseJSON.get('data'))
        #running on the API server but does not exist in Snyk
        #print(responseJSON['data'][0]['relationships'])
        #The None only works if the image has NEVER been scanned, after it has been scanned it we keep some data around
        #print(responseJSON['data'][0]['relationships']['image_target_refs'])
        if responseJSON.get('data') == None or 'data' not in responseJSON['data'][0]['relationships']['image_target_refs']:
            needsToBeScanned.append(container.image)


scanMissingImages(needsToBeScanned)
deleteNonRunningTargets()

    
