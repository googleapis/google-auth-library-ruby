#!groovy

@Library("liveramp-base@v1") _

pipeline {
  options {
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '50'))
    ansiColor('xterm')
  }

  triggers {
    // Github hook to build whenever a commit is pushed
    githubPush()

    // Github hook to build whenever 'jenkins please' is in a comment on github
    issueCommentTrigger('.*jenkins\\W+(((test|build|run|do)\\W+this)|again|git\\W+r\\W+done|please|make it so).*')
  }

  agent any

  environment {
    RUBYGEMS_HOST = 'https://private-gems.liveramp.net'
  }

  stages {
    stage('gem:ci') {
      steps {
        sh 'bundle install --path=.bundle-gems'
        sh 'bundle exec rake ci'
      }
    }

    stage('gem:release') {
      when { branch 'master' }
      steps {
        withCredentials( bindings:
          // CredentialsId was found through the credentials page for
          // jenkins_publisher/****** (library.liveramp.net)
          [
            usernamePassword(
            credentialsId: 'library.liveramp.net--jenkins_publisher',
            usernameVariable: 'ARTIFACTORY_USERNAME',
            passwordVariable: 'ARTIFACTORY_PASSWORD'
            ),
          ]) {
            sh 'bundle exec rake ci_release'
        }
      }
    }
  }

  post {
    always {
      slackNotification('#dev-ops-builds', 'master')
    }
  }
}
