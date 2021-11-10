#include <QGuiApplication>
#include <QQuickView>

#include <QtDebug>

Q_DECL_EXPORT int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    const QStringList args = app.arguments();
    if (args.size() > 2) {
        qWarning() << "Usage: cryptoqmlexample [--test]\n";
        qWarning() << "If the optional --test argument is provided, the daemon must be started in --test mode.";
        return 0;
    }

    QQuickView view;
    view.setSource(QUrl("qrc:/main.qml"));
    view.showFullScreen();

    return app.exec();
}
