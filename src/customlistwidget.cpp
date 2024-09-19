#include "customlistwidget.h"
#include <QAction>
#include <QHBoxLayout>
#include <QLabel>

CustomListWidget::CustomListWidget(QWidget *parent)
    : QListWidget(parent)
{
    setContextMenuPolicy(Qt::CustomContextMenu);
    connect(this, &QListWidget::customContextMenuRequested, this, &CustomListWidget::showContextMenu);

    contextMenu = new QMenu(this);
    QAction *removeAction = new QAction("Remove", this);
    connect(removeAction, &QAction::triggered, this, &CustomListWidget::removeSelectedItem);
    contextMenu->addAction(removeAction);

    setMouseTracking(true);
    viewport()->installEventFilter(this);
}

QStringList CustomListWidget::getAllItems() const
{
    QStringList items;
    for (int i = 0; i < count(); ++i) {
        QWidget *widget = itemWidget(item(i));
        QLabel *label = widget->findChild<QLabel*>();
        if (label) {
            items << label->text();
        }
    }
    return items;
}

void CustomListWidget::addItem(const QString &label)
{
    QListWidgetItem *item = new QListWidgetItem(this);
    setupItemWidget(item, label);
    QListWidget::addItem(item);
}

void CustomListWidget::setupItemWidget(QListWidgetItem *item, const QString &text)
{
    QWidget *widget = new QWidget(this);
    QHBoxLayout *layout = new QHBoxLayout(widget);
    layout->setContentsMargins(5, 2, 5, 2);
    layout->setSpacing(10);

    QLabel *label = new QLabel(text, widget);
    layout->addWidget(label);

    QPushButton *deleteButton = new QPushButton("X", widget);
    deleteButton->setFixedSize(20, 20);
    deleteButton->setStyleSheet("QPushButton { background-color: red; color: white; border: none; border-radius: 10px; }");
    deleteButton->hide();
    layout->addWidget(deleteButton);

    layout->addStretch();

    widget->setLayout(layout);
    item->setSizeHint(widget->sizeHint());
    setItemWidget(item, widget);

    connect(deleteButton, &QPushButton::clicked, this, &CustomListWidget::removeItem);
}

void CustomListWidget::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Delete) {
        removeSelectedItem();
    } else {
        QListWidget::keyPressEvent(event);
    }
}

bool CustomListWidget::eventFilter(QObject *obj, QEvent *event)
{
    if (obj == viewport()) {
        if (event->type() == QEvent::MouseMove) {
            QMouseEvent *mouseEvent = static_cast<QMouseEvent*>(event);
            QListWidgetItem *item = itemAt(mouseEvent->pos());
            for (int i = 0; i < count(); ++i) {
                QWidget *widget = itemWidget(this->item(i));
                if (widget) {
                    QPushButton *deleteButton = widget->findChild<QPushButton*>();
                    if (deleteButton) {
                        deleteButton->setVisible(this->item(i) == item);
                    }
                }
            }
        }
    }
    return QListWidget::eventFilter(obj, event);
}

void CustomListWidget::showContextMenu(const QPoint &pos)
{
    QPoint globalPos = mapToGlobal(pos);
    contextMenu->exec(globalPos);
}

void CustomListWidget::removeSelectedItem()
{
    QList<QListWidgetItem*> items = selectedItems();
    for (QListWidgetItem *item : items) {
        delete takeItem(row(item));
    }
}

void CustomListWidget::removeItem()
{
    QPushButton *deleteButton = qobject_cast<QPushButton*>(sender());
    if (deleteButton) {
        QWidget *widget = deleteButton->parentWidget();
        for (int i = 0; i < count(); ++i) {
            if (itemWidget(item(i)) == widget) {
                delete takeItem(i);
                break;
            }
        }
    }
}