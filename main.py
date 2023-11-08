import requests as reqs
from kubernetes import client, config
import json
import os
import time 
import sys

#Globals, probably worth changing these to environment variables or mounting them from a configmap


#Scan any missing images, 'images' should be a iterable list
#We can modify the arguments of Snyk Container to include tags which can then be used to create project views or import metadata from the pods if needed
def scanMissingImages(images):
    splitKey = APIKEY.split()

    cmd = '/usr/local/bin/snyk auth {}'.format(splitKey[1])
    os.system(cmd)
    for missingImage in images:

        #cmd = '/usr/app/sec/snyk container monitor {} --org={} --tags=kubernetes=monitored'.format(missingImage, orgId)
        print("Scanning {}").format(missingImage)
        cmd = '/usr/local/bin/snyk container monitor {} --org={} --tags=kubernetes=monitored'.format(missingImage, orgId)
        os.system(cmd)

def deleteNonRunningTargets():

    #May be worth building in a retry mechanism instead of just failing
    #Also both endpoints only cover the case where there is no nextPage key, adding in 'while next page != empty' will probably be nessisary for larger datasets
    try:
        containerImageURL = "https://api.snyk.io/rest/orgs/{}/container_images?version={}".format(orgId, snykAPIVersion)
        containerResponse = reqs.get(containerImageURL, headers={'Authorization': '{}'.format(APIKEY)})
        containerResponseJSON = containerResponse.json()
        containerResponse.raise_for_status()
    except reqs.HTTPError as ex:
        print("ERROR: some error occured dumping target JSON {}".format(containerResponseJSON))
        raise ex
    except reqs.Timeout:
        print("ERROR: Request to the container_images endpoint timed out, returning without completing")
        raise ex

    try:
        allTargetsUrl = "https://api.snyk.io/rest/orgs/{}/targets?version={}".format(orgId, snykAPIVersion)
        targetResponse = reqs.get(allTargetsUrl, headers={'Authorization': '{}'.format(APIKEY)})
        targetResponseJSON = targetResponse.json()
        targetResponse.raise_for_status()
        
    except reqs.HTTPError as ex:
        print("ERROR: some error occured dumping target JSON {}".format(targetResponseJSON))
        raise ex
    except reqs.Timeout:
        print("ERROR: Request to the Targets endpoint timed out, returning without completing")
        raise ex        



    for containerImage in containerResponseJSON['data']:
        image = containerImage['attributes']['names'][0]

        #image that is not running on the cluster   
        if image not in allRunningPods:

            #TODO: change the split to replace for '_', depending on the workflow it may make more sense to create targets with <image>_<version>
            imageTagStripped = image.split(':')
            imageTagStripped = imageTagStripped[0]
            for target in targetResponseJSON['data']:
                if target['attributes']['displayName'] == imageTagStripped:
                    deleteTargetURL = "https://api.snyk.io/rest/orgs/{}/targets/{}?version={}".format(orgId,target['id'], snykAPIVersion)
                    deleteResp = reqs.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                    if deleteResp.status_code == 204:
                        print("succesfully delete targetID {}, based off image {}".format(target['id'], imageTagStripped))
                    else:
                        print("Some issue deleting targetID {}, based off image {}. Response code: {}".format(target['id'], imageTagStripped, deleteResp.status_code))


#Load Kubeconfig for interacting with the K8s API. Load in K8s api V1 to query pods. 
if os.getenv('KUBERNETES_SERVICE_HOST'):
    print("KUBERNETES_SERVICE_HOST detected, atempting to load in pod config... ")
    config.load_incluster_config() 
else:
    print("KUBERNETES_SERVICE_HOST is not set, loading kubeconfig from localhost...")
    config.load_kube_config()
v1 = client.CoreV1Api()

#vars for later logic
allRunningPods = []
needsToBeScanned = []


for pod in v1.list_pod_for_all_namespaces().items:
    
    for container in pod.spec.containers: 
        image= container.image
        allRunningPods.append(container.image)

        #will need to add some retry logic incase the connection dies
        URL = "https://api.snyk.io/rest/orgs/{}/container_images?names={}&version={}".format(orgId, image, snykAPIVersion)
        
        try:
            response = reqs.get(URL, headers={'Authorization': '{}'.format(APIKEY)})
            responseJSON = response.json()
        except reqs.HTTPError as ex:
            print("ERROR: Some error has occured, dumping response JSON: {}".format(responseJSON))
            raise ex
        except reqs.Timeout:
            print("ERROR: Request to the container_images endpoint timed out for image {}".format(image))
            
        #These are running on the API server but do not exist in Snyk
        #The None only works if the image has NEVER been scanned, after it has been scanned it we keep some data around
        if responseJSON.get('data') == None or 'data' not in responseJSON['data'][0]['relationships']['image_target_refs']:
            needsToBeScanned.append(container.image)


#Do the work we have set out to do o7
if len(needsToBeScanned) != 0:
    scanMissingImages(needsToBeScanned)
else:
    print("All images on the cluster are accounted for, skipping scanning function")

#For some reason it seemed like there was an issue with data being present if there was no delay
#Might be safe to remove but for now I am just letting Snyk do some work in the background to ensure everyhting is
#where we are expecting it to be
time.sleep(5)
deleteNonRunningTargets()

#clean exit when
sys.exit()