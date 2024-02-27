import requests as reqs
from kubernetes import client, config
import os
import sys

#Globals, probably worth adding in some sort of direct failure here if these are not set
APIKEY = os.getenv("APIKEY")
ORGID = os.getenv("ORGID")
SNYKAPIVERSION = os.getenv("SNYKAPIVERSION")
SNYKDEBUG = os.getenv("SNYKDEBUG")
DOCKERPASSWORD = os.getenv("DOCKERPASSWORD")
DOCKERUSER = os.getenv("DOCKERUSER")

APIKEY = "Token " + APIKEY


#Scan any missing images, 'images' should be a iterable list
#We can modify the arguments of Snyk Container to include tags which can then be used to create project views or import metadata from the pods if needed
#Tags seem like an easy way to say 'this is monitored on your cluster / through this script'
def scanMissingImages(images):
    splitKey = APIKEY.split()

    #Auth the CLI
    cmd = '/usr/local/bin/snyk auth {}'.format(splitKey[1])
    os.system(cmd)
    
    for missingImage in images:


        print("Scanning {}".format(missingImage))

        if bool(SNYKDEBUG) == True:
            cmd = '/usr/local/bin/snyk container monitor {} -d --org={} --username={} --password={} --tags=kubernetes=monitored'.format(missingImage, ORGID, DOCKERUSER, DOCKERPASSWORD)
        else:
            cmd = '/usr/local/bin/snyk container monitor {} --org={} --username={} --password={} --tags=kubernetes=monitored'.format(missingImage, ORGID, DOCKERUSER, DOCKERPASSWORD)

        os.system(cmd)


def deleteNonRunningTargets():

    #May be worth building in a retry mechanism instead of just failing
    fullListofContainers = []
    try:
        containerImageUrl = "https://api.snyk.io/rest/orgs/{}/container_images?version={}&limit=100".format(ORGID, SNYKAPIVERSION)
        while True:
            containerResponse = reqs.get(containerImageUrl, headers={'Authorization': APIKEY})
            containerResponse.raise_for_status()
            containerResponseJSON = containerResponse.json()
            fullListofContainers.extend(containerResponseJSON['data'])
            nextPageUrl = containerResponseJSON['links'].get('next')
            if not nextPageUrl:
                break
            containerImageUrl = "https://api.snyk.io/{}&version={}&limit=100".format(nextPageUrl, SNYKAPIVERSION)
    except reqs.HTTPError as ex:
        print("ERROR: HTTP error occurred while fetching container images:", ex)
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
    except reqs.Timeout:
        print("ERROR: Request to the container_images endpoint timed out, returning without completing")
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


    fullListOfProjects = []
    try:
        allProjectsURL = "https://api.snyk.io/rest/orgs/{}/projects?version={}&limit=100".format(ORGID, SNYKAPIVERSION)
        while True:
            projectResponse = reqs.get(allProjectsURL, headers={'Authorization': APIKEY})
            projectResponse.raise_for_status()
            projectResponseJSON = projectResponse.json()
            fullListOfProjects.extend(projectResponseJSON['data'])
            nextPageProjectURL = projectResponseJSON['links'].get('next')
            if not nextPageProjectURL:
                break
            allProjectsURL = "https://api.snyk.io/{}&version={}&limit=100".format(nextPageProjectURL, SNYKAPIVERSION)
    except reqs.HTTPError as ex:
        print("ERROR: HTTP error occurred while fetching projects:", ex)
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
        raise ex
    except reqs.Timeout:
        print("ERROR: Request to the projects endpoint timed out, returning without completing")
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
        raise ex    

    for containerImage in fullListofContainers:

        #Snyk keeps deleted images around for 8 days, there shouldn't be target refs for images that have been deleted
        #We need to skip these due to how Snyk displays targets in the UI, if apiServer:1.27.2 is around after being deleted
        # and we are monitoring apiServer 1.27.3 actively the below checks will delete apiServer 1.27.3 as the target for both is 'registry/apiServer'
        if containerImage['relationships']['image_target_refs']['links'].get('self') is None:
            continue

        for imageName in containerImage['attributes']['names']:

            #No SHA support as of now
            if '@' in imageName:
                continue
            
            if imageName not in allRunningPods and not any(imageName in subString for subString in allRunningPods):
                imageTagStripped = imageName.split(':')[0]
                deletedTargetIDs= []         
                for project in fullListOfProjects:
                    if project['relationships']['target']['data']['id'] in deletedTargetIDs:
                        continue
                    if imageTagStripped in project['attributes']['target_reference']:
                        deleteTargetURL = "https://api.snyk.io/rest/orgs/{}/targets/{}?version={}".format(ORGID,project['relationships']['target']['data']['id'], SNYKAPIVERSION)
                        deleteResp = reqs.delete(deleteTargetURL, headers={'Authorization': '{}'.format(APIKEY)})
                        deletedTargetIDs.append(project['relationships']['target']['data']['id'])
                        if deleteResp.status_code == 204:
                            print("succesfully deleted targetID {}, based off image {}".format(project['relationships']['target']['data']['id'], imageTagStripped))
                            continue
                        else:
                            print("Some issue deleting targetID {}, based off image {}. Response code: {}".format(project['relationships']['target']['data']['id'], imageTagStripped, deleteResp.status_code))
                            continue                       
 



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

    multiContainerPod = pod.status.container_statuses

    for container in pod.spec.containers: 
        image = container.image
        
        if 'a1doll/k8sreconciler' in image:
            continue
        
        if ':' not in image:
            for imagesInContainer in multiContainerPod:
                if image in imagesInContainer.image:
                    image = imagesInContainer.image

        allRunningPods.append(image)
        
        #will need to add some retry logic incase the connection dies
        URL = "https://api.snyk.io/rest/orgs/{}/container_images?names={}&version={}".format(ORGID, image, SNYKAPIVERSION)
        
        try:
            print("Sending request to the container images endpoint for {}".format(image))
            response = reqs.get(URL, headers={'Authorization': '{}'.format(APIKEY)})
            responseJSON = response.json()
        except reqs.HTTPError as ex:
            print("ERROR: Some error has occured, dumping response JSON: {}".format(responseJSON))
            print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            raise ex
        except reqs.Timeout:
            print("ERROR: Request to the container_images endpoint timed out for image {}".format(image))
        
        #These are running on the API server but do not exist in Snyk
        #The None only works if the image has NEVER been scanned, after it has been scanned it we keep some data around
        if not responseJSON.get('data'):
            print("{} does not exist in Snyk, adding it to the queue to be scanned".format(image))
            needsToBeScanned.append(image)
        else:
            imageExists = any('self' in target['relationships']['image_target_refs']['links'] for target in responseJSON['data'])
        if not imageExists:
            print("{} does not exist in Snyk, adding it to the queue to be scanned".format(image))            
            needsToBeScanned.append(image)


#Do the work we have set out to do
if len(needsToBeScanned) != 0:
    scanMissingImages(needsToBeScanned)
else:
    print("All images on the cluster are accounted for, skipping scanning function")

deleteNonRunningTargets()
sys.exit()