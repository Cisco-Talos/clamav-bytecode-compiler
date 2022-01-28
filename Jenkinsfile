properties(
    [
        disableConcurrentBuilds(),
        buildDiscarder(logRotator(
            artifactDaysToKeepStr: '15',
            artifactNumToKeepStr: '15',
            daysToKeepStr: '30',
            numToKeepStr: '20')),
        parameters(
            [
                string(name: 'VERSION',
                       defaultValue: '1.0',
                       description: 'bcc version string'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '0.104',
                       description: 'test-framework branch'),
                string(name: 'BUILD_BRANCH',
                       defaultValue: 'master',
                       description: 'test-bcc branch for building  bcc'),
                string(name: 'TESTS_BRANCH',
                       defaultValue: 'tests',
                       description: 'test-bcc branch for testing  bcc'),
                string(name: 'SHARED_LIB_BRANCH',
                       defaultValue: 'master',
                       description: 'tests-jenkins-shared-libraries branch'),
                string(name: 'TEST_PIPELINE_PATH',
                       defaultValue: 'bcc/test_bcc/',
                       description: 'path for test pipelines'),

            ]
        )
    ]
)

def buildResult

node('master') {

    cleanWs()

    stage('Build-BCC') {

        // checkout target code
        dir("bcc") {
            checkout scm
        }

        sh "tar -zcvf bcc_source.tar.gz bcc"

        archiveArtifacts artifacts: 'bcc_source.tar.gz'

        buildResult = build(job: "${params.TEST_PIPELINE_PATH}${params.BUILD_BRANCH}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'BCC_JOB_NAME', value: "${JOB_NAME}"],
                [$class: 'StringParameterValue', name: 'BCC_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                [$class: 'StringParameterValue', name: 'BUILD_BRANCH', value: "${params.BUILD_BRANCH}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "${params.TEST_PIPELINE_PATH}${params.BUILD_BRANCH} #${buildResult.number} succeeded."
    }

    stage('Test-BCC') {
        buildResult = build(job: "${params.TEST_PIPELINE_PATH}${params.TESTS_BRANCH}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_BRANCH}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "${params.TEST_PIPELINE_PATH}/${params.TESTS_BRANCH} #${buildResult.number} succeeded."
    }
}
