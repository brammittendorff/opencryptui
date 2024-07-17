#ifndef CUSTOMLISTWIDGET_H
#define CUSTOMLISTWIDGET_H

#include <QListWidget>
#include <QStringList>

class CustomListWidget : public QListWidget
{
    Q_OBJECT

public:
    explicit CustomListWidget(QWidget *parent = nullptr);

    QStringList getAllItems() const;
};

#endif // CUSTOMLISTWIDGET_H
