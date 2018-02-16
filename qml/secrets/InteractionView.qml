import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Secrets 1.0 as Secrets

// TODO: replace this with "actual UI" which allows user to confirm/deny or enter a custom password!
Item {
    Rectangle {
        id: deleteConfirmationItem
        visible: adapter.requestType == Secrets.ApplicationInteractionView.DeleteSecretConfirmationRequest
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
            onClicked: adapter.confirmation = Secrets.ApplicationInteractionView.Allow
        }
    }
    Rectangle {
        id: modifyConfirmationItem
        visible: adapter.requestType == Secrets.ApplicationInteractionView.ModifySecretConfirmationRequest
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
            onClicked: adapter.confirmation = Secrets.ApplicationInteractionView.Allow
        }
    }
    Rectangle {
        id: userVerificationConfirmationItem
        visible: adapter.requestType == Secrets.ApplicationInteractionView.UserVerificationConfirmationRequest
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
            onClicked: adapter.confirmation = Secrets.ApplicationInteractionView.Allow
        }
    }
    Rectangle {
        id: encryptionPasswordItem
        visible: adapter.requestType == Secrets.ApplicationInteractionView.AuthenticationKeyRequest
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
