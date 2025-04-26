# datasource/wiz.py
import datetime
import logging
import json
import os
from typing import List, Dict, Any, Optional
from wiz_sdk import WizAPIClient

# Required environment variables for using this datasource
WIZ_ENV = os.getenv("WIZ_ENV")
WIZ_CLIENT_ID = os.getenv("WIZ_CLIENT_ID")
WIZ_CLIENT_SECRET = os.getenv("WIZ_CLIENT_SECRET")
WIZ_API_PROXY = os.getenv("WIZ_API_PROXY")
WIZ_CLOUD_ACCOUNT_OR_ORGANIZATION_ID = os.getenv("WIZ_CLOUD_ACCOUNT_OR_ORGANIZATION_ID")

def fetch_cloudtrail_events(
    days: int,
    role: Optional[str],
    options: Optional[Dict]
) -> List[Dict[str, Any]]:
    """
    Retrieve CloudTrail events from the past `days` days using Wiz API.

    :param days: How many days' worth of events to fetch
    :return: A list of CloudTrail event dictionaries
    """

    # Check all envs have been set
    if not WIZ_ENV or not WIZ_CLIENT_ID or not WIZ_CLIENT_SECRET or not WIZ_CLOUD_ACCOUNT_OR_ORGANIZATION_ID:
        raise RuntimeError("Missing required environment variables. Please set WIZ_ENV, WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, and WIZ_CLOUD_ACCOUNT_OR_ORGANIZATION_ID.")

    if days < 1 or days > 90:
        raise ValueError("Days parameter must be between 1 and 90 (inclusive); "
                         "the Wiz API only supports a max of 90 days.")
    
    informational_string = "Fetching CloudTrail events from Wiz, "

    if role:
        informational_string += f"for Role='{role}', "
    else:
        informational_string += f"with no Role filter, "

    informational_string += f"from the past {days} days..."
    logging.info(informational_string)

    end_time = datetime.datetime.utcnow()
    start_time = end_time - datetime.timedelta(days=days)

    # Format timestamps for Wiz API
    end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # Configure Wiz API client
    conf = {
        'wiz_env': WIZ_ENV,  # Set to "gov" or "fedramp" if applicable
        'wiz_client_id': WIZ_CLIENT_ID,  # Your Service Account Client ID
        'wiz_client_secret': WIZ_CLIENT_SECRET,  # Your Service Account Client Secret
        'wiz_api_proxy': WIZ_API_PROXY  # Set proxy if needed
    }

    # Initialize Wiz API client
    client = WizAPIClient(conf=conf)

    # Define GraphQL query
    query = """
    query CloudEventsTable($after: String, $first: Int, $filterBy: CloudEventFilters, $groupBy: CloudEventGroupBy, $orderDirection: OrderDirection, $projectId: [String!], $includeCount: Boolean!, $includeExtraDetails: Boolean!, $includeProcessEntitiesIssueAnalytics: Boolean = false, $includeThreatActors: Boolean = false, $includeDynamicDescription: Boolean = false, $includeAggregatedEventDetails: Boolean = false, $includeCustomIPRanges: Boolean = false, $includeIssueAnalytics: Boolean = true, $includePublicExposurePaths: Boolean = false, $includeInternalExposurePaths: Boolean = false, $includeLateralMovement: Boolean = false, $includeKubernetes: Boolean = false, $includeCost: Boolean = false, $includeMatchedRules: Boolean = false, $includeGroupPercentage: Boolean = false) {
      cloudEvents(
        filterBy: $filterBy
        first: $first
        after: $after
        groupBy: $groupBy
        orderDirection: $orderDirection
        projectId: $projectId
      ) {
        nodes {
          ... on CloudEventGroupByResult {
            values
            count @include(if: $includeCount)
            groupPercentage @include(if: $includeGroupPercentage)
            cloudEvents {
              id
              name
              timestamp
              cloudPlatform
              category
              hash
              commandLine
              severity
              kind
              dnsQuery
              cloudAccount {
                ...CloudEventCloudAccount
              }
              cloudOrganization {
                ...CloudEventCloudCloudOrganization
              }
              networkConnection {
                destinationIp
                destinationPort
                sourceIp
                sourcePort
              }
              runtimeProgram {
                id
                name
                userId
                scriptName
                isDrifted
              }
              parentRuntimeProgram {
                id
                name
                userId
                scriptName
              }
              kind
              externalName
              origin
              path
              imageDigests
              imageNames
              imageGraphEntities {
                id
                type
                name
              }
              cloudNativeService
              actorIP
              actorIPMeta {
                city
                country
                countryCode
                reputation
                reputationSource
                autonomousSystemOrganization
                autonomousSystemNumber
              }
              isForeignActorIP
              actor {
                email
                type
                nativeType
                name
                id
                userAgent
                externalId
                cloudAccount {
                  ...CloudEventCloudAccount
                }
                accessKeyId
                actingAs {
                  ...CloudEventActorActingAs
                }
                providerUniqueId
              }
              subjectResource {
                id
                type
                externalId
                name
                nativeType
                region
                providerUniqueId
                cloudAccount {
                  ...CloudEventCloudAccount
                }
                containerService {
                  id
                  name
                  providerUniqueId
                }
                kubernetesClusterGraphEntity {
                  id
                  name
                  providerUniqueId
                }
                kubernetesCluster {
                  id
                  name
                  providerUniqueId
                }
                kubernetesNamespace {
                  id
                  name
                  providerUniqueId
                }
                vcsRepository {
                  id
                  name
                }
                openToAllInternet
              }
              matchedRules {
                rule {
                  builtInId
                  name
                  id
                }
              }
              errorMessage
              errorCode
              status
              statusDetails {
                errorReason
                providerErrorCode
                providerErrorMessage
              }
            }
            resourceCloudAccount {
              ...CloudEventCloudAccount
            }
          }
          ... on CloudEvent {
            id
            name
            externalId
            externalName
            cloudPlatform
            timestamp
            rawAuditLogRecord
            category
            kind
            origin
            severity
            path
            impactedFilePath
            hash
            cloudNativeService
            commandLine
            imageDigests
            imageNames
            matchedRules @include(if: $includeMatchedRules) {
              rule {
                builtInId
                name
                id
              }
            }
            imageGraphEntities {
              id
              type
              name
            }
            statusDetails {
              errorReason
              providerErrorCode
              providerErrorMessage
            }
            aggregatedEventDetails @include(if: $includeAggregatedEventDetails) {
              eventsCount
            }
            description @include(if: $includeDynamicDescription)
            dnsQuery
            dnsRequest {
              type
              query
              queryBaseDomain
              queryMeta {
                reputation
                reputationSource
                reputationDescription
              }
              responses {
                type
                response
                meta {
                  city
                  country
                  countryCode
                  reputation
                  reputationSource
                  reputationDescription
                  autonomousSystemOrganization
                }
              }
            }
            networkConnection {
              destinationIp
              destinationResource {
                id
                externalId
                name
                type
              }
              destinationIpMeta {
                ...CloudEventNetworkConnectionIPMeta
              }
              destinationPort
              sourceIp
              sourceResource {
                id
                externalId
                name
                type
              }
              sourceIpMeta {
                ...CloudEventNetworkConnectionIPMeta
              }
              sourcePort
              protocol {
                name
                number
              }
              packetsTransferred
              bytesTransferred
              duration
            }
            runtimeProgram {
              id
              name
              userId
              scriptName
              isDrifted
            }
            parentRuntimeProgram {
              id
              name
              userId
              scriptName
            }
            actorIP
            actorIPMeta {
              relatedAttackGroupNames @include(if: $includeThreatActors)
              city
              country
              countryCode
              reputation
              reputationSource
              autonomousSystemOrganization
              autonomousSystemNumber
              customIPRanges @include(if: $includeCustomIPRanges) {
                id
                name
                isInternal
              }
            }
            isForeignActorIP
            actor {
              ...CloudEventActorDetails
            }
            actorActingAsGraphEntity {
              id
              name
              type
              properties
              providerUniqueId
              deletedAt
              isRestricted
              ...CloudEventGraphEntityLayersFragment
            }
            subjectResourceGraphEntity {
              id
              name
              type
              properties
              providerUniqueId
              deletedAt
              isRestricted
              ...CloudEventGraphEntityLayersFragment
            }
            actorGraphEntity {
              id
              name
              type
              properties
              providerUniqueId
              deletedAt
              isRestricted
              ...CloudEventGraphEntityLayersFragment
            }
            subjectResource {
              id
              type
              name
              nativeType
              externalId
              providerUniqueId
              region
              cloudAccount {
                ...CloudEventCloudAccount
              }
              containerService {
                id
                name
                type
                providerUniqueId
              }
              containerServiceGraphEntity {
                id
                name
                type
                providerUniqueId
              }
              kubernetesClusterGraphEntity {
                id
                name
                type
                providerUniqueId
              }
              kubernetesCluster {
                id
                name
                type
                providerUniqueId
              }
              kubernetesNamespaceGraphEntity {
                id
                name
                providerUniqueId
              }
              kubernetesNamespace {
                id
                name
                providerUniqueId
              }
              kubernetesControllerGraphEntity {
                id
                name
                type
                providerUniqueId
              }
              kubernetesController {
                id
                name
                type
                providerUniqueId
              }
              vcsRepository {
                id
                name
              }
              openToAllInternet
            }
            cloudAccount {
              ...CloudEventCloudAccount
            }
            cloudOrganization {
              ...CloudEventCloudCloudOrganization
            }
            errorCode
            errorMessage
            status
            ...CloudEventExtraDetails @include(if: $includeExtraDetails)
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
        totalCount @include(if: $includeCount)
        maxCountReached
      }
    }
    
        fragment CloudEventCloudAccount on CloudAccount {
      id
      externalId
      name
      cloudProvider
    }
    

        fragment CloudEventCloudCloudOrganization on CloudOrganization {
      id
      externalId
      name
      cloudProvider
    }
    

        fragment CloudEventActorActingAs on CloudEventActor {
      id
      name
      friendlyName
      externalId
      providerUniqueId
      type
    }
    

        fragment CloudEventNetworkConnectionIPMeta on CloudEventIPMeta {
      country
      countryCode
      city
      reputation
      reputationSource
    }
    

        fragment CloudEventActorDetails on CloudEventActor {
      id
      externalId
      name
      email
      friendlyName
      type
      nativeType
      userAgent
      accessKeyId
      cloudAccount {
        ...CloudEventCloudAccount
      }
      hasAdminPrivileges
      hasHighPrivileges
      hasAdminKubernetesPrivileges
      hasHighKubernetesPrivileges
      isExternalCloudAccount
      inactiveInLast90Days
      MFA
      actingAs {
        ...CloudEventActorActingAs
      }
      providerUniqueId
    }
    

        fragment CloudEventGraphEntityLayersFragment on GraphEntity {
      issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $includeIssueAnalytics) {
        highSeverityCount
        criticalSeverityCount
      }
      publicExposures(first: 10) @include(if: $includePublicExposurePaths) {
        nodes {
          ...CloudEventNetworkExposureFragment
        }
      }
      lateralMovementPaths(first: 10) @include(if: $includeLateralMovement) {
        nodes {
          id
          pathEntities {
            entity {
              ...CloudEventPathGraphEntityFragment
            }
          }
        }
      }
      kubernetesPaths(first: 10) @include(if: $includeKubernetes) {
        nodes {
          id
          path {
            ...CloudEventPathGraphEntityFragment
          }
        }
      }
      otherSubscriptionExposures(first: 10) @include(if: $includeInternalExposurePaths) {
        nodes {
          ...CloudEventNetworkExposureFragment
        }
      }
      cost(
        filterBy: {timestamp: {inLast: {amount: 30, unit: DurationFilterValueUnitDays}}}
      ) @include(if: $includeCost) {
        amortized
        blended
        unblended
        netAmortized
        netUnblended
        currencyCode
      }
    }
    

        fragment CloudEventNetworkExposureFragment on NetworkExposure {
      id
      portRange
      sourceIpRange
      destinationIpRange
      path {
        ...CloudEventPathGraphEntityFragment
      }
      applicationEndpoints {
        ...CloudEventPathGraphEntityFragment
      }
    }
    

        fragment CloudEventPathGraphEntityFragment on GraphEntity {
      id
      name
      type
      properties
      issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $includeIssueAnalytics) {
        highSeverityCount
        criticalSeverityCount
      }
    }
    

        fragment CloudEventExtraDetails on CloudEvent {
      extraDetails {
        ...CloudEventRuntimeDetails
        ...CloudEventAdmissionReviewDetails
        ...CloudEventFimDetails
        ...CloudEventImageIntegrityDetails
        ...CloudEventCICDScanDetails
      }
      trigger {
        ...CloudEventSensorRulesMatch
        ...CloudEventAdmissionReviewTriggerDetails
      }
    }
    

        fragment CloudEventRuntimeDetails on CloudEventRuntimeDetails {
      sensor {
        id
        name
        lastSeenAt
        firstSeenAt
        sensorVersion
        definitionsVersion
        status
        ipAddress
        type
        workload {
          id
          name
          sensorName
        }
        cluster {
          id
          name
          type
        }
        group {
          id
        }
      }
      processTree {
        ...CloudEventRuntimeProcessBasicDetails
        userName
        userId
        hash
        executionTime
        runtimeProgramId
        stdin
        stdout
        name
        wizResponse
        enforcementResult {
          action
          errorMessage
        }
        containerGraphEntity {
          ...ProcessResourceGraphEntity
          ...ProcessResourceGraphEntityLayers
          isRestricted
          properties
          issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $includeProcessEntitiesIssueAnalytics) {
            highSeverityCount
            criticalSeverityCount
          }
        }
        container {
          id
          name
          externalId
          imageGraphEntity {
            ...ProcessResourceGraphEntity
          }
          image {
            id
            externalId
          }
          podGraphEntity {
            ...ProcessResourceGraphEntity
          }
          pod {
            id
            name
            externalId
            ips
            namespace
            namespaceGraphEntity {
              ...ProcessResourceGraphEntity
            }
          }
          kubernetesControllerGraphEntity {
            ...ProcessResourceGraphEntity
          }
          kubernetesController {
            id
            name
            externalId
            type
          }
          kubernetesClusterGraphEntity {
            ...ProcessResourceGraphEntity
          }
          kubernetesCluster {
            id
            name
            externalId
          }
          serviceAccount
          ecsContainerDetails {
            ecsTask {
              id
              externalId
            }
            ecsTaskGraphEntity {
              ...ProcessResourceGraphEntity
            }
            ecsCluster {
              id
              name
              externalId
            }
            ecsClusterGraphEntity {
              ...ProcessResourceGraphEntity
            }
            ecsService {
              id
              name
              externalId
            }
            ecsServiceGraphEntity {
              ...ProcessResourceGraphEntity
            }
          }
        }
      }
      hostGraphEntity {
        properties
        isRestricted
        ...ProcessResourceGraphEntity
        issueAnalytics: issues(filterBy: {status: [IN_PROGRESS, OPEN]}) @include(if: $includeProcessEntitiesIssueAnalytics) {
          highSeverityCount
          criticalSeverityCount
        }
        ...ProcessResourceGraphEntityLayers
      }
      host {
        id
        externalId
        type
        hostname
        kernelVersion
        computeInstanceGroupGraphEntity {
          id
          name
          type
        }
      }
      rawDetails
      runtimeExecutionDataId
      type
      context {
        ... on CloudEventRuntimeTypeFileContext {
          fileName
        }
        ... on CloudEventRuntimeTypeNetworkConnectContext {
          remoteIP
          remotePort
        }
        ... on CloudEventRuntimeTypeDNSQueryContext {
          query
        }
        ... on CloudEventRuntimeTypeProcessStartContext {
          commandLine
        }
        ... on CloudEventRuntimeTypeIMDSQueryContext {
          query
        }
        ... on CloudEventRuntimeTypeChangeDirectoryContext {
          path
        }
      }
    }
    

        fragment CloudEventRuntimeProcessBasicDetails on CloudEventRuntimeProcess {
      id
      command
      path
      executionTime
      runtimeProgramId
    }
    

        fragment ProcessResourceGraphEntity on GraphEntity {
      id
      name
      type
      kubernetesPaths(first: 0) {
        totalCount
      }
    }
    

        fragment ProcessResourceGraphEntityLayers on GraphEntity {
      publicExposures(first: 10) @include(if: $includePublicExposurePaths) {
        nodes {
          ...CloudEventNetworkExposureFragment
        }
      }
      lateralMovementPaths(first: 10) @include(if: $includeLateralMovement) {
        nodes {
          id
          pathEntities {
            entity {
              ...CloudEventPathGraphEntityFragment
            }
          }
        }
      }
      kubernetesPathsFull: kubernetesPaths(first: 10) @include(if: $includeKubernetes) {
        nodes {
          id
          path {
            ...CloudEventPathGraphEntityFragment
          }
        }
      }
      otherSubscriptionExposures(first: 10) @include(if: $includeInternalExposurePaths) {
        nodes {
          ...CloudEventNetworkExposureFragment
        }
      }
      cost(
        filterBy: {timestamp: {inLast: {amount: 30, unit: DurationFilterValueUnitDays}}}
      ) @include(if: $includeCost) {
        amortized
        blended
        unblended
        netAmortized
        netUnblended
        currencyCode
      }
    }
    

        fragment CloudEventAdmissionReviewDetails on CloudEventAdmissionReviewDetails {
      verdict
      policyEnforcement
      reviewDuration
      infoMatches
      lowMatches
      mediumMatches
      highMatches
      criticalMatches
      totalMatches
      policies {
        ...CICDScanPolicyDetails
      }
      cloudConfigurationFindings {
        cloudConfigurationRule {
          id
          shortId
          name
          severity
          cloudProvider
        }
        passedPolicies {
          ...CICDScanPolicyDetails
        }
        failedPolicies {
          ...CICDScanPolicyDetails
        }
      }
    }
    

        fragment CICDScanPolicyDetails on CICDScanPolicy {
      id
      name
      description
      policyLifecycleEnforcements {
        enforcementMethod
        deploymentLifecycle
      }
      params {
        __typename
        ... on CICDScanPolicyParamsIAC {
          severityThreshold
        }
        ... on CICDScanPolicyParamsVulnerabilities {
          severity
        }
        ... on CICDScanPolicyParamsSensitiveData {
          dataFindingSeverityThreshold
        }
        ... on CICDScanPolicyParamsSecrets {
          secretFindingSeverityThreshold
        }
        ... on CICDScanPolicyParamsHostConfiguration {
          hostConfigurationSeverity
          rulesScope {
            type
            securityFrameworks {
              id
              name
            }
          }
          failCountThreshold
          passPercentageThreshold
        }
        ... on CICDScanPolicyParamsSoftwareSupplyChain {
          softwareSupplyChainSeverityThreshold
        }
      }
    }
    

        fragment CloudEventFimDetails on CloudEventFimDetails {
      previousHash
    }
    

        fragment CloudEventImageIntegrityDetails on CloudEventImageIntegrityAdmissionReviewDetails {
      verdict
      policyEnforcement
      reviewDuration
      policies {
        ...CICDScanPolicyDetails
      }
      images {
        id
        name
        imageVerdict
        sources
        digest
        policiesFailedBasedOnNoMatchingValidators {
          id
          name
        }
        imageIntegrityValidators {
          imageIntegrityValidator {
            ...ImageSignatureValidatorDetails
          }
          verdict
          failedPolicies {
            ...CICDScanPolicyDetails
          }
          passedPolicies {
            ...CICDScanPolicyDetails
          }
          extraDetails {
            ... on ImageIntegrityAdmissionReviewImageValidatorExtraDetailsWizScan {
              cicdScan {
                id
                status {
                  verdict
                }
              }
            }
          }
        }
      }
    }
    

        fragment ImageSignatureValidatorDetails on ImageIntegrityValidator {
      id
      name
      description
      imagePatterns
      projects {
        id
        isFolder
        slug
        name
      }
      value {
        method
        notary {
          certificate
        }
        cosign {
          method
          key
          certificate
          certificateChain
        }
        wizScan {
          maxAgeHours
          policyId
          serviceAccountIds
        }
      }
    }
    

        fragment CloudEventCICDScanDetails on CloudEventCICDScanDetails {
      cicdScanPolicyEnforcement: policyEnforcement
      scanDuration
      trigger
      scanType: type
      tags {
        key
        value
      }
      createdBy {
        serviceAccount {
          id
          name
        }
        user {
          id
          name
          email
        }
      }
      cliDetails {
        ...CICDScanCLIDetailsFragment
      }
      codeAnalyzerDetails {
        taskUrl
        commit {
          author
          infoURL
          messageSnippet
          ref
          sha
          committedAt
        }
        webhookEvent {
          createdAt
          hookID
          payload
          processedAt
          receivedAt
          source
          sourceRequestID
          type
          wizRequestID
        }
        pullRequest {
          author
          title
          baseCommit {
            sha
            ref
            infoURL
          }
          headCommit {
            sha
            ref
            infoURL
          }
          bodySnippet
          infoURL
          analytics {
            additions
            deletions
            changedFiles
            commits
          }
        }
      }
      warnedPolicies {
        ...CICDScanPolicyDetails
      }
      failedPolicies {
        ...CICDScanPolicyDetails
      }
      passedPolicies {
        ...CICDScanPolicyDetails
      }
      policies {
        ...CICDScanPolicyDetails
      }
      secretDetails {
        failedPolicyMatches {
          ...CICDScanPolicyMatch
        }
        secrets {
          id
          contains {
            name
            type
          }
          details {
            __typename
          }
          failedPolicyMatches {
            ...CICDScanPolicyMatch
          }
          ignoredPolicyMatches {
            ...CICDScanPolicyMatch
          }
          description
          lineNumber
          offset
          path
          snippet
          type
          severity
          hasAdminPrivileges
          hasHighPrivileges
          relatedEntities {
            id
            type
            name
            properties
          }
        }
        analytics {
          cloudKeyCount
          dbConnectionStringCount
          gitCredentialCount
          passwordCount
          privateKeyCount
          totalCount
        }
      }
      softwareSupplyChainDetails {
        failedPolicyMatches {
          ...CICDScanPolicyMatch
        }
        findings {
          codeLibrary {
            name
            version
            path
          }
          failedPolicyMatches {
            ...CICDScanPolicyMatch
          }
          licenseNames
          licenseCategory
          name
          severity
        }
      }
      malwareDetails {
        findings {
          path
          malwareDetails {
            name
            severity
            confidenceLevel
            sha1
          }
          failedPolicyMatches {
            ...CICDScanPolicyMatch
          }
        }
        analytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
          totalCount
        }
      }
      iacDetails {
        ruleMatches {
          rule {
            id
            shortId
            name
            description
            cloudProvider
          }
          deletedRuleFallback: rule {
            id
            name
          }
          severity
          failedResourceCount
          failedPolicyMatches {
            ...CICDScanPolicyMatch
          }
          matches {
            resourceName
            fileName
            lineNumber
            matchContent
            expected
            found
            ignoredPolicyMatches {
              ...CICDScanPolicyMatch
            }
          }
        }
        scanStatistics {
          infoMatches
          lowMatches
          highMatches
          mediumMatches
          criticalMatches
          totalMatches
        }
      }
      hostConfigurationDetails {
        ...HostConfigurationDetails
      }
      vulnerabilityDetails {
        vulnerableSBOMArtifactsByNameVersion {
          ...CICDSbomArtifactsByNameVersion
        }
        cpes {
          name
          version
          path
          vulnerabilities {
            ...CICDScanDiskScanVulnerabilityDetails
          }
          detectionMethod
        }
        osPackages {
          name
          version
          vulnerabilities {
            ...CICDScanDiskScanVulnerabilityDetails
          }
          detectionMethod
        }
        libraries {
          name
          version
          path
          vulnerabilities {
            ...CICDScanDiskScanVulnerabilityDetails
          }
          detectionMethod
        }
        applications {
          name
          vulnerabilities {
            path
            pathType
            version
            vulnerability {
              ...CICDScanDiskScanVulnerabilityDetails
            }
          }
          detectionMethod
        }
        analytics {
          vulnerabilities {
            infoCount
            lowCount
            mediumCount
            highCount
            criticalCount
            totalCount
          }
          filesScannedCount
          directoriesScannedCount
        }
      }
      dataDetails {
        dataFindingsWithFullClassifierInfo: findings {
          dataClassifier {
            id
            name
            category
            originalDataClassifierOverridden
          }
          ...CICDScanDataFindingDetails
        }
        dataFindings: findings {
          dataClassifier {
            id
            name
          }
          ...CICDScanDataFindingDetails
        }
      }
      status {
        details
        state
        verdict
      }
      policies {
        __typename
        id
        name
        params {
          __typename
        }
      }
      analytics {
        vulnerabilityScanResultAnalytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
        }
        dataScanResultAnalytics {
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
        }
        iacScanResultAnalytics {
          infoCount: infoMatches
          lowCount: lowMatches
          mediumCount: mediumMatches
          highCount: highMatches
          criticalCount: criticalMatches
        }
        secretScanResultAnalytics {
          cloudKeyCount
          dbConnectionStringCount
          gitCredentialCount
          passwordCount
          privateKeyCount
          saasAPIKeyCount
          infoCount
          lowCount
          mediumCount
          highCount
          criticalCount
          totalCount
        }
      }
      infoMatches
      lowMatches
      mediumMatches
      highMatches
      criticalMatches
      totalMatches
    }
    

        fragment CICDScanCLIDetailsFragment on CICDScanCLIDetails {
      scanOriginResource {
        name
        __typename
        ... on CICDScanOriginIAC {
          subTypes
          name
        }
        ... on CICDScanOriginContainerImage {
          digest
          id
          name
        }
      }
      scanOriginResourceType
      clientName
      clientVersion
      buildParams {
        commitUrl
        branch
        commitHash
        committedBy
        platform
        repository
        extraDetails {
          ... on CICDBuildParamsContainerImage {
            dockerfilePath
            dockerfileContents
          }
        }
      }
    }
    

        fragment CICDScanPolicyMatch on CICDScanPolicyMatch {
      ignoreReason
      policy {
        id
        name
        params {
          ... on CICDScanPolicyParamsHostConfiguration {
            failCountThreshold
            passPercentageThreshold
            rulesScope {
              type
            }
          }
        }
      }
      matchedIgnoreRules {
        id
        name
        origin
        findingIgnoreReason
        vcsOriginContext {
          commentURL
          userProvidedReason
        }
      }
    }
    

        fragment HostConfigurationDetails on CICDHostConfigurationScanResult {
      hostConfigurationFrameworks {
        framework {
          id
          name
        }
        matches {
          analytics {
            severity {
              infoCount
              lowCount
              mediumCount
              highCount
              criticalCount
            }
            status {
              passCount
              failCount
              errorCount
              notAssessedCount
              totalCount
            }
          }
          policyMatch {
            policy {
              id
            }
          }
        }
      }
      hostConfigurationFindings {
        rule {
          description
          name
          id
          securitySubCategories {
            id
            resolutionRecommendation
            title
            description
            category {
              id
              name
              framework {
                id
                name
                enabled
              }
            }
          }
        }
        status
        severity
        failedPolicyMatches {
          ...CICDScanPolicyMatch
        }
        ignoredPolicyMatches {
          ...CICDScanPolicyMatch
        }
      }
    }
    

        fragment CICDSbomArtifactsByNameVersion on CICDDiskScanResultSBOMArtifactsByNameVersion {
      id
      name
      version
      filePath
      vulnerabilityFindings {
        fixedVersion
        remediation
        severities {
          criticalCount
          highCount
          infoCount
          lowCount
          mediumCount
        }
        findings {
          id
          vulnerabilityExternalId
          remediationPullRequestAvailable
          remediationPullRequestConnector {
            id
            name
            type {
              id
              name
            }
          }
          severity
        }
      }
      layerMetadata {
        id
        isBaseLayer
        details
      }
      type {
        ...SBOMArtifactTypeFragment
      }
    }
    

        fragment SBOMArtifactTypeFragment on SBOMArtifactType {
      group
      codeLibraryLanguage
      osPackageManager
      hostedTechnology {
        id
        name
        icon
      }
      plugin
      custom
    }
    

        fragment CICDScanDiskScanVulnerabilityDetails on DiskScanVulnerability {
      name
      description
      severity
      fixedVersion
      source
      score
      exploitabilityScore
      hasExploit
      hasCisaKevExploit
      cisaKevReleaseDate
      cisaKevDueDate
      epssProbability
      epssPercentile
      epssSeverity
      publishDate
      fixPublishDate
      gracePeriodEnd
      gracePeriodRemainingHours
      ignoredPolicyMatches {
        ...CICDScanPolicyMatch
      }
      failedPolicyMatches {
        ...CICDScanPolicyMatch
      }
      weightedSeverity
      finding {
        id
        version
        status
      }
    }
    

        fragment CICDScanDataFindingDetails on CICDDiskScanResultDataFinding {
      matchCount
      severity
      examples {
        path
        matchCount
        value
      }
      ignoredPolicyMatches {
        ...CICDScanPolicyMatch
      }
      failedPolicyMatches {
        ...CICDScanPolicyMatch
      }
    }
    

        fragment CloudEventSensorRulesMatch on CloudEventSensorRulesMatch {
      sensorEngineRules {
        rule {
          id
          name
          description
          MITRETactics
          MITRETechniques
        }
        version
      }
      fileReputationHashMatch {
        name
        md5
        sha1
        sha256
        sampleFirstSeen
        sampleLastSeen
        scannerMatch
        scannerCount
        scannerPercent
        trustFactor
        malwareClassification {
          isGeneric
          type
          platform
          subPlatform
          family
          vulnerability {
            id
          }
        }
      }
      connectivityReputation {
        source {
          ip
          port
        }
        destination {
          ip
          ipReputation
          port
        }
        process {
          ...CloudEventRuntimeProcessBasicDetails
        }
      }
      dnsQueryReputation {
        domain
        domainReputation
        process {
          ...CloudEventRuntimeProcessBasicDetails
        }
      }
    }
    

        fragment CloudEventAdmissionReviewTriggerDetails on CloudEventAdmissionReview {
      cloudConfigurationRuleMatches {
        cloudConfigurationRule {
          id
        }
        cicdScanPolicies {
          id
          name
          params {
            __typename
          }
        }
      }
    }
    """

    role_filter = {}
    if role:
        operation = "equals"
        if "*" in role:
            operation = "contains"
            role = role.replace("*", "")
        role_filter = {
            operation: [role]
        }

    variables = {
        "includeProcessEntitiesIssueAnalytics": False,
        "includeThreatActors": False,
        "includeDynamicDescription": False,
        "includeAggregatedEventDetails": True,
        "includeCustomIPRanges": False,
        "includeIssueAnalytics": True,
        "includePublicExposurePaths": False,
        "includeInternalExposurePaths": False,
        "includeLateralMovement": False,
        "includeKubernetes": False,
        "includeCost": False,
        "includeMatchedRules": False,
        "includeGroupPercentage": False,
        "includeExtraDetails": False,
        "includeCount": False,
        "orderDirection": "DESC",
        "filterBy": {
            "and": [
            {
                "timestamp": {
                    "inLast": {
                        "unit": "DurationFilterValueUnitDays",
                        "amount": days
                    }
                },
                "cloudAccountOrCloudOrganizationId": {
                    "equals": [
                        WIZ_CLOUD_ACCOUNT_OR_ORGANIZATION_ID
                    ]
                },
                "actor": {
                    "actingAsExternalId": role_filter
                }
            }
            ]
        }
    }
    logging.info(f"Wiz query filter: {variables['filterBy']}")

    parsed_events = []
    try:
        # Query Wiz API
        results_responses = client.query(query, variables)
        if not results_responses:
            logging.error(f"No results found in the response. Something likely went wrong with the query.")
            return []

        for results_response in results_responses:
            if not results_response:
                logging.error(f"No result item found in this response page; results may be incomplete.")
                continue

            parsed_events.append({
                "EventId": results_response.get("externalId"),
                "EventName": results_response.get("rawAuditLogRecord", {}).get("eventName"),
                "ReadOnly": results_response.get("rawAuditLogRecord", {}).get("readOnly"),
                "AccessKeyId": results_response.get("rawAuditLogRecord", {}).get("userIdentity", {}).get("accessKeyId"),
                "EventTime": results_response.get("rawAuditLogRecord", {}).get("eventTime"),
                "EventSource": results_response.get("rawAuditLogRecord", {}).get("eventSource"),
                "Username": results_response.get("actor", {}).get("email"),
                "Resources": results_response.get("rawAuditLogRecord", {}).get("resources"),
                "CloudTrailEvent": json.dumps(results_response.get("rawAuditLogRecord"))
            })
    except Exception as e:
        logging.error(f"Error fetching events from Wiz API: {e}")
        return []

    return parsed_events
