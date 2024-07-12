#include "mainwindow.h"
#include <QApplication>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    // Create an instance of MainWindow
    MainWindow w;

    // Check if there are any other instances of MainWindow
    QWidgetList topLevelWidgets = QApplication::topLevelWidgets();
    int mainWindowCount = 0;
    for (QWidget *widget : topLevelWidgets) {
        if (qobject_cast<MainWindow*>(widget)) {
            mainWindowCount++;
        }
    }

    // Print the number of MainWindow instances
    qDebug() << "Number of MainWindow instances:" << mainWindowCount;

    // Show the MainWindow
    w.show();

    return a.exec();
}