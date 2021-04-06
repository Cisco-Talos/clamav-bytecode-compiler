properties(
    [
        disableConcurrentBuilds(),
        parameters(
            [
                string(name: 'BCC_BRANCH',
                       defaultValue: "${env.BRANCH_NAME}",
                       description: 'bcc branch to test against'),
                string(name: 'VERSION',
                       defaultValue: '1.0',
                       description: 'bcc version string'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '0.104',
                       description: 'test-framework branch'),
                string(name: 'TESTS_BRANCH',
                       defaultValue: 'master',
                       description: 'tests branch'),
                string(name: 'BUILD_PIPELINE',
                       defaultValue: 'master',
                       description: 'test-bcc branch for building  bcc'),
                string(name: 'TEST_PIPELINE',
                       defaultValue: 'test-bcc',
                       description: 'test-bcc branch for building  bcc'),
                string(name: 'SHARED_LIB_BRANCH',
                       defaultValue: 'bcc-shared-lib',
                       description: 'tests-jenkins-shared-libraries branch')
            ]
        )
    ]
)

def buildResult

node('master') {
    stage('Build-BCC') {
        buildResult = build(job: "test-bcc/${params.BUILD_PIPELINE}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'TARGET_BRANCH', value: "${params.BCC_BRANCH}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "test-bcc/${params.BUILD_PIPELINE} #${buildResult.number} succeeded."
    }

    stage('Test-BCC') {
        buildResult = build(job: "test-bcc/${params.TEST_PIPELINE}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_BRANCH}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "test-bcc/${params.TEST_PIPELINE} #${buildResult.number} succeeded."
    }
}
