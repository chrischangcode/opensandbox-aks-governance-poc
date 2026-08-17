targetScope = 'resourceGroup'

@description('Existing AKS cluster whose kubelet identity pulls images.')
param aksName string

@description('Existing Azure Container Registry.')
param acrName string

var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource cluster 'Microsoft.ContainerService/managedClusters@2024-10-01' existing = {
  name: aksName
}

resource registry 'Microsoft.ContainerRegistry/registries@2023-07-01' existing = {
  name: acrName
}

resource kubeletAcrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(registry.id, cluster.id, acrPullRoleId)
  scope: registry
  properties: {
    principalId: cluster.properties.identityProfile.kubeletidentity.objectId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
  }
}

output roleAssignmentName string = kubeletAcrPull.name
