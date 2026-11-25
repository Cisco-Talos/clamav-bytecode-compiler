pipeline {
    agent none

    options {
        disableConcurrentBuilds()
        disableRestartFromStage()
        skipDefaultCheckout()
        buildDiscarder(logRotator(
            artifactDaysToKeepStr: '15',
            artifactNumToKeepStr: '15',
            daysToKeepStr: '30',
            numToKeepStr: '20'
        ))
    }

    parameters {
        string(name: 'VERSION',
               defaultValue: '1.4.0',
               description: 'bcc version string')
        string(name: 'FRAMEWORK_BRANCH',
               defaultValue: '1.4',
               description: 'test-framework branch')
        string(name: 'BUILD_BRANCH',
               defaultValue: 'main',
               description: 'test-bcc branch for building  bcc')
        string(name: 'TESTS_BRANCH',
               defaultValue: 'tests',
               description: 'test-bcc branch for testing  bcc')
        string(name: 'SHARED_LIB_BRANCH',
               defaultValue: 'main',
               description: 'tests-jenkins-shared-libraries branch')
        string(name: 'TEST_PIPELINE_PATH',
               defaultValue: 'clamav/clambcc/test_bcc',
               description: 'path for test pipelines')
    }

    stages {
        stage('Build-BCC') {
            agent { label 'default' }

            steps {
                cleanWs()
                dir('bcc') {
                    checkout scm
                }

                sh 'tar -zcvf bcc_source.tar.gz bcc'
                archiveArtifacts artifacts: 'bcc_source.tar.gz'

                script {
                    def buildJob = "${params.TEST_PIPELINE_PATH}${params.BUILD_BRANCH}"
                    def buildResult = build(
                        job: buildJob,
                        propagate: true,
                        wait: true,
                        parameters: [
                            string(name: 'BCC_JOB_NAME', value: env.JOB_NAME),
                            string(name: 'BCC_JOB_NUMBER', value: env.BUILD_NUMBER),
                            string(name: 'BUILD_BRANCH', value: params.BUILD_BRANCH),
                            string(name: 'FRAMEWORK_BRANCH', value: params.FRAMEWORK_BRANCH),
                            string(name: 'VERSION', value: params.VERSION),
                            string(name: 'SHARED_LIB_BRANCH', value: params.SHARED_LIB_BRANCH)
                        ]
                    )
                    env.BCC_BUILD_JOB_NUMBER = buildResult.number.toString()
                    echo "${buildJob} #${env.BCC_BUILD_JOB_NUMBER} succeeded."
                }
            }
        }

        stage('Test-BCC') {
            agent { label 'default' }

            steps {
                script {
                    def testJob = "${params.TEST_PIPELINE_PATH}${params.TESTS_BRANCH}"
                    def testResult = build(
                        job: testJob,
                        propagate: true,
                        wait: true,
                        parameters: [
                            string(name: 'TESTS_BRANCH', value: params.TESTS_BRANCH),
                            string(name: 'BUILD_JOB_NAME', value: "${params.TEST_PIPELINE_PATH}${params.BUILD_BRANCH}"),
                            string(name: 'BUILD_JOB_NUMBER', value: env.BCC_BUILD_JOB_NUMBER),
                            string(name: 'FRAMEWORK_BRANCH', value: params.FRAMEWORK_BRANCH),
                            string(name: 'VERSION', value: params.VERSION),
                            string(name: 'SHARED_LIB_BRANCH', value: params.SHARED_LIB_BRANCH)
                        ]
                    )
                    echo "${testJob} #${testResult.number} succeeded."
                }
            }
        }
    }
}
