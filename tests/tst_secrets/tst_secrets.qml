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
            InProcessUiView {
                id: uiview
                objectName: "uiview"
                anchors.fill: parent
            }
        }
    }
}
