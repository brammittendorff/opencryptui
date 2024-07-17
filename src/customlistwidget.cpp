#include "customlistwidget.h"

CustomListWidget::CustomListWidget(QWidget *parent)
    : QListWidget(parent)
{
}

QStringList CustomListWidget::getAllItems() const
{
    QStringList items;
    for (int i = 0; i < count(); ++i) {
        items << item(i)->text();
    }
    return items;
}
