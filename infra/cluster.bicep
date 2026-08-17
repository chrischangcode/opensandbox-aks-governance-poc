targetScope = 'resourceGroup'

@description('Azure region used for the AKS cluster and optional registry.')
param location string = resourceGroup().location

@description('Name of the AKS cluster.')
param aksName string

@description('Name of the Azure Container Registry. An empty value skips registry creation.')
param acrName string = ''

@description('VM size for the AKS system node pool.')
param nodeVmSize string = 'Standard_D4s_v3'

@minValue(1)
@description('Number of nodes in the AKS system node pool.')
param systemNodeCount int = 1

@description('Optional Kubernetes version. An empty value selects the regional default.')
param kubernetesVersion string = ''

@description('Enable ACR admin credentials for development-only fallback flows.')
param acrAdminUserEnabled bool = false

@description('Tags applied to created Azure resources.')
param tags object = {
  workload: 'opensandbox-governance-poc'
}

var createRegistry = !empty(acrName)
var versionConfiguration = empty(kubernetesVersion) ? {} : {
  kubernetesVersion: kubernetesVersion
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' = if (createRegistry) {
  name: acrName
  location: location
  tags: tags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: acrAdminUserEnabled
    publicNetworkAccess: 'Enabled'
  }
}

resource cluster 'Microsoft.ContainerService/managedClusters@2024-10-01' = {
  name: aksName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: union({
    dnsPrefix: aksName
    enableRBAC: true
    oidcIssuerProfile: {
      enabled: true
    }
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      loadBalancerSku: 'standard'
      outboundType: 'loadBalancer'
    }
    agentPoolProfiles: [
      {
        name: 'systempool'
        mode: 'System'
        count: systemNodeCount
        vmSize: nodeVmSize
        osType: 'Linux'
        osSKU: 'AzureLinux'
        type: 'VirtualMachineScaleSets'
        enableAutoScaling: false
      }
    ]
  }, versionConfiguration)
}

output aksName string = cluster.name
output acrLoginServer string = createRegistry ? registry!.properties.loginServer : ''
output acrAdminUserEnabled bool = createRegistry ? acrAdminUserEnabled : false
