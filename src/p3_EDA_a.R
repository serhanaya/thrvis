# Visual Analysis of Cyber Threat. Part 3_a: Exploratory Analysis
# Serhan Aya 2016-07-02.

# After getting the data from the web, some columns
# are manipulated in order to further understand the
# relationships of the data. In this part, the data
# is explored using various visualization approaches.

# Load required packages
library(feather)    # Load dataframe
library(lubridate)  # Date manipulation
library(plyr)       # Data manipulation
library(dplyr)      # Data manipulation
library(treemap)    # Visualization (Treemap)
library(zoo)        # Date manipulation
library(ggplot2)    # Visualization

# Load data (cleaned).
df <- read_feather("data/tVDClean.feather")

# Q1: What are the most frequent viruses?

# Count number of Viruses listed under NName column.
virCount <- plyr::count(df, "NName")
virCount <- virCount %>%
    arrange(desc(freq))

# Treemap plot of most frequent 30 viruses.
treemap(virCount[1:30,], index="NName", vSize="freq", vColor="freq",
        type="value", palette="RdYlBu",
        title="Treemap of Most Frequent Viruses",
        title.legend = "Frequency")

dev.copy(png, filename="figure/treemap-names.png", width=1920, height=1080)
dev.off ()

# Another plot showing the most frequent Viruses and their frequency.
ggplot(virCount[1:15,], aes(x=freq, y=reorder(NName, freq))) +
    geom_point(size=3) +
    theme_bw() +
    theme(panel.grid.major.x = element_blank(),
          panel.grid.minor.x = element_blank(),
          panel.grid.major.y = element_line(colour="grey60", linetype="dashed"))+
    labs(x="Frequency", y="Virus Name", title="Most Frequent Viruses")

# Q2: How frequent are the most frequent viruses (according to NType prefix)
#     seen?

# df is grouped and counted according to `NType` column.
df.NType.count <- df %>%
    group_by(NType, DateDiscovered) %>%
    summarise(type.count=n())

# Variables sorted according to their counts.
top.vir.NType <- plyr::count(df.NType.count, "NType")
top.vir.NType <- top.vir.NType %>%
    arrange(desc(freq))

# Top 3 virus names are listed, and their count is determined
# with `Date`.
top.vir.NType.nameList <- top.vir.NType$NType[1:3]
df.top.NType.count <- df.NType.count %>%
    filter(NType %in% top.vir.NType.nameList)

# Following is the timeseries boxplot of top 3 virus `NType`.
# There are some serious outliers in the data which blocks
# the clear visualization.
ggplot(df.top.NType.count, aes(x=factor(as.yearmon(DateDiscovered)), y=type.count,
                               fill=NType)) + geom_boxplot()+
    labs(x=NULL, y="Count", title="Timeseries Boxplot of Most Frequent NType Viruses")

# After removing the outliers from the observed data
# The timeseries boxplot clearly shows the change of frequency
# of the top 3 viruses according to `NType`.
ggplot(df.top.NType.count[df.top.NType.count$type.count < 50 ,],
       aes(x=factor(as.yearmon(DateDiscovered)), y=type.count, fill=NType))+
    geom_boxplot()+
    labs(x=NULL, y="Count", title="Timeseries Boxplot of Most Frequent NType Viruses")

# Q2: How frequent are the most frequent viruses (according to Type prefix)
#     seen?

# The distribution of viruses by type:
ggplot(df, aes(x=Type)) + geom_bar(colour='black') +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))+
    labs(x=NULL, y="Count", title="The Distribution of Viruses by Type")

# df is grouped and counted according to `Type` column.
df.type.count <- df %>%
    group_by(Type, DateDiscovered) %>%
    summarise(type.count=n())

# Variables sorted according to their counts.
top.vir.type <- plyr::count(df.type.count, "Type")
top.vir.type <- top.vir.type %>%
    arrange(desc(freq))

# Top 3 virus names are listed, and their count is determined
# with `Date`.
top.vir.type.nameList <- top.vir.type$Type[1:3]
df.top.type.count <- df.type.count %>%
    filter(Type %in% top.vir.type.nameList)

# Following is the timeseries boxplot of top 3 virus `Type`.
# There are some serious outliers in the data which blocks
# the clear visualization.
ggplot(df.top.type.count, aes(x=factor(as.yearmon(DateDiscovered)), y=type.count, fill=Type))+
    geom_boxplot()+
    labs(x=NULL, y="Count", title="Time Series Boxplot of Most Frequent Type Viruses")

# After removing the outliers from the observed data
# The timeseries boxplot clearly shows the change of frequency
# of the top 3 viruses according to `Type`.
ggplot(df.top.type.count[df.top.type.count$type.count < 50 ,],
       aes(x=factor(as.yearmon(DateDiscovered)), y=type.count, fill=Type))+
    geom_boxplot()+
    labs(x=NULL, y="Count", title="Time Series Boxplot of Most Frequent Type Viruses")

# Q4: Which operating system is affected the most?

# Variation of OS (bar_chart)
ggplot(df, aes(x=OS)) + geom_bar(colour='black') +
    theme(axis.text.x = element_text(angle = 45, hjust = 1))+
    labs(x=NULL, y="Count", title="The Distribution of Viruses by OS")

# Q5: How are the impacts of the viruses? Does the percentage of the
#     different levels of impact change with the changing
#     frequency?

# Explore: Impact (Low, Medium, High)

# Create a dataframe counting the numbers of different levels of
# impact per month.
temp.impact <- df %>%
    select(Impact, DateDiscovered) %>%
    na.omit() %>%
    mutate(Month = as.yearmon(DateDiscovered)) %>%
    select(Impact, Month) %>%
    group_by(Impact, Month) %>%
    summarise(Count = n())

temp.impact <- ddply(temp.impact, "Month", transform,
                     Percent.impact = Count / sum(Count) * 100)

# Following is a bar chart showing the total number of viruses per
# month. Each bar filled (colored) with levels of impact.
ggplot(temp.impact, aes(x=as.Date(Month), y=Count, fill=Impact)) +
    geom_bar(stat="identity", colour="black") +
    guides(fill=guide_legend(reverse=TRUE))+
    scale_fill_brewer(palette="Pastel1")+
    scale_x_date(date_breaks = "1 month", date_labels = "%b %Y")+
    theme(axis.text.x = element_text(angle = 0, hjust = 0.5))+
    labs(x=NULL, y="Count", title="Impact of Viruses")

# Impact: Stacked bar_chart/month showing the percentage of different levels
# of impact for each month.
ggplot(temp.impact, aes(x=as.Date(Month), y=Percent.impact, fill=Impact)) +
    geom_bar(stat="identity", colour="black") +
    guides(fill=guide_legend(reverse=TRUE)) +
    scale_fill_brewer(palette="Pastel1")+
    scale_x_date(date_breaks = "1 month", date_labels = "%b %Y")+
    theme(axis.text.x = element_text(angle = 0, hjust = 0.5)) +
    labs(x=NULL, y="Percentage Impact", title="Impact of Viruses")

# Q6: How are the infections of the viruses? Does the percentage of the
#     different levels of infections change with the changing
#     frequency?

# Explore: Infections (Low, Medium, High)
# Create a dataframe counting the numbers of infections
# per month
temp.infect <- df %>%
    select(Infections, DateDiscovered) %>%
    na.omit() %>%
    mutate(Month = as.yearmon(DateDiscovered)) %>%
    select(Infections, Month) %>%
    group_by(Infections, Month) %>%
    summarise(Count = n())

temp.infect <- ddply(temp.infect, "Month", transform,
      Percent.infect = Count / sum(Count) * 100)

# Following is a bar chart showing the total number of viruses per
# month. Each bar filled (colored) with levels of infection.
ggplot(temp.infect, aes(x=as.Date(Month), y=Count, fill=Infections)) +
    geom_bar(stat="identity", colour="black") +
    guides(fill=guide_legend(reverse=TRUE))+
    scale_fill_brewer(palette="Pastel1")+
    scale_x_date(date_breaks = "1 month", date_labels = "%b %Y")+
    theme(axis.text.x = element_text(angle = 0, hjust = 0.5))+
    labs(x=NULL, y="Count", title="Infections of Viruses")

# Stacked bar_chart/month showing the percentage of different levels
# of infections for each month.
ggplot(temp.infect, aes(x=as.Date(Month), y=Percent.infect, fill=Infections)) +
    geom_bar(stat="identity", colour="black") +
    guides(fill=guide_legend(reverse=TRUE)) +
    scale_fill_brewer(palette="Pastel1")+
    scale_x_date(date_breaks = "1 month", date_labels = "%b %Y")+
    theme(axis.text.x = element_text(angle = 0, hjust = 0.5))+
    labs(x=NULL, y="Percentage Infections", title="Infections of Viruses")
