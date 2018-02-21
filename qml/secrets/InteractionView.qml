import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Secrets 1.0 as Secrets

// TODO: replace this with "actual UI" which allows user to confirm/deny or enter a custom password!
Item {
    Rectangle {
        id: deleteConfirmationItem
        visible: adapter.interactionParameters.inputType == Secrets.InteractionParameters.ConfirmationInput
                 && adapter.interactionParameters.operation == Secrets.InteractionParameters.DeleteSecret
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
        visible: adapter.interactionParameters.inputType == Secrets.InteractionParameters.ConfirmationInput
                 && adapter.interactionParameters.operation == Secrets.InteractionParameters.StoreSecret
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
        visible: adapter.interactionParameters.inputType == Secrets.InteractionParameters.AuthenticationInput
        enabled: visible
        anchors.fill: parent
        color: "yellow"
        Text {
            anchors.centerIn: parent
            text: "PRESS ME TO AUTHENTICATE/CONTINUE"
        }
        MouseArea {
            enabled: parent.enabled
            anchors.fill: parent
            onClicked: adapter.confirmation = Secrets.ApplicationInteractionView.Allow
        }
    }
    Rectangle {
        id: encryptionPasswordItem
        visible: adapter.interactionParameters.inputType == Secrets.InteractionParameters.AlphaNumericInput
        enabled: visible
        anchors.fill: parent
        color: "red"
        Text {
            anchors.centerIn: parent
            text: "PRESS ME TO SUPPLY PASSWORD/CONTINUE"
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
