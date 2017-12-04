import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Secrets 1.0

ApplicationWindow {
    id: root
    initialPage: secretsUi
    Component {
        id: secretsUi
        Page {
            id: page
            InProcessInteractionView {
                id: interactionview
                objectName: "interactionview"
                anchors.fill: parent
            }
        }
    }
}
