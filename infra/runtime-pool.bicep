targetScope = 'resourceGroup'

@description('Existing AKS cluster that receives the runtime node pool.')
param aksName string

@description('Name of the new AKS agent pool.')
param poolName string

@description('VM size used by the runtime pool.')
param nodeVmSize string = 'Standard_D4s_v3'

@minValue(1)
@description('Number of nodes in the runtime pool.')
param nodeCount int = 1

@allowed([
  'kata'
  'gvisor'
  'firecracker'
])
@description('Runtime experiment assigned to this node pool.')
param runtimeKind string

var usesKataIsolation = runtimeKind == 'kata'
var runtimeTaint = '${runtimeKind}=true:NoSchedule'
var kataSettings = usesKataIsolation ? {
  workloadRuntime: 'KataMshvVmIsolation'
} : {}

resource cluster 'Microsoft.ContainerService/managedClusters@2024-10-01' existing = {
  name: aksName
}

resource pool 'Microsoft.ContainerService/managedClusters/agentPools@2024-10-01' = {
  name: poolName
  parent: cluster
  properties: union({
    count: nodeCount
    vmSize: nodeVmSize
    mode: 'User'
    osType: 'Linux'
    osSKU: 'AzureLinux'
    type: 'VirtualMachineScaleSets'
    enableAutoScaling: false
    nodeLabels: {
      'runtime-experiment': runtimeKind
    }
    nodeTaints: [
      runtimeTaint
    ]
  }, kataSettings)
}

output poolName string = pool.name
output runtimeKind string = runtimeKind
