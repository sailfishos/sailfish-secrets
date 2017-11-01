import QtQuick 2.0
import Sailfish.Silica 1.0
import org.sailfishos.secrets 1.0 as Secrets

// TODO: replace this with "actual UI" which allows user to confirm/deny or enter a custom password!
Item {
    Rectangle {
        id: deleteConfirmationItem
        visible: adapter.requestType == Secrets.InProcessUiView.DeleteSecretConfirmationRequest
        enabled: visible
        anchors.fill: parent
        color: "blue"
        Text {
            anchors.centerIn: parent
            text: "PRESS ME TO DELETE/CONTINUE"
        }
        MouseArea {
            enabled: parent.enabled
            anchors.fill: parent
            onClicked: adapter.confirmation = Secrets.InProcessUiView.Allow
        }
    }
    Rectangle {
        id: modifyConfirmationItem
        visible: adapter.requestType == Secrets.InProcessUiView.ModifySecretConfirmationRequest
        enabled: visible
        anchors.fill: parent
        color: "green"
        Text {
            anchors.centerIn: parent
            text: "PRESS ME TO MODIFY/CONTINUE"
        }
        MouseArea {
            enabled: parent.enabled
            anchors.fill: parent
            onClicked: adapter.confirmation = Secrets.InProcessUiView.Allow
        }
    }
    Rectangle {
        id: userVerificationConfirmationItem
        visible: adapter.requestType == Secrets.InProcessUiView.UserVerificationConfirmationRequest
        enabled: visible
        anchors.fill: parent
        color: "yellow"
        Text {
            anchors.centerIn: parent
            text: "PRESS ME TO VERIFY/CONTINUE"
        }
        MouseArea {
            enabled: parent.enabled
            anchors.fill: parent
            onClicked: adapter.confirmation = Secrets.InProcessUiView.Allow
        }
    }
    Rectangle {
        id: encryptionPasswordItem
        visible: adapter.requestType == Secrets.InProcessUiView.AuthenticationKeyRequest
        enabled: visible
        anchors.fill: parent
        color: "red"
        Text {
            anchors.centerIn: parent
            text: "PRESS ME TO AUTH/CONTINUE"
        }
        MouseArea {
            enabled: parent.enabled
            anchors.fill: parent
            onClicked: {
                console.log("returning custom encryption password!")
                adapter.password = "example custom password"
            }
        }
    }
}
