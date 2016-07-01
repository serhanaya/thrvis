# Visual Analysis of Cyber Threat. Part 3_b: Exploratory Analysis - Heatmap
# Serhan Aya 2016-07-02.

# This is a subsection for Part 3: Exploratory Analysis. In this
# section the explorations are focused on the following questions:
# Q7  : Which virus has the highest impact?
# Q8  : What is the most infective virus amongst others?
# Q9  : Which virus has the longest lifetime?
# Q10  : How long has these viruses are around/ and known that they
#       are around (i.e. they are documented)?
# Q11 : How many of those viruses are relatively inactive?
# Q12 : Which viruses update the most, as well as the least?

# Load required packages
library(feather)    # Load dataframe
library(lubridate)  # Date manipulation
library(plyr)       # Data manipulation
library(dplyr)      # Data manipulation

# Load dataframe
df <- read_feather("data/tVDClean.feather")

# Count number of Viruses listed under NName column.
virCount <- plyr::count(df, "NName")
virCount <- virCount %>%
    arrange(desc(freq))

# Q7  : Which virus has the highest impact?

# `norm.impact` function counts the different
# levels of impact differently (`High`: 3, `Medium`: 2,
# `Low`: 1) and normalizes the according values.
# The function takes two arguments: The first is the dataframe to work on,
# the second is the virus name to investigate. The function returns sum
# of normalized count value for a given virus.
norm.impact <- function(df, virName) {
    tot.df <- df %>%
        na.omit() %>%
        group_by(Impact) %>%
        summarise(count = n())

    tot.high <- filter(tot.df, Impact=="High") %>% select(count)
    tot.med <- filter(tot.df, Impact=="Medium") %>% select(count)
    tot.low <- filter(tot.df, Impact=="Low") %>% select(count)

    temp.df <- df %>%
        na.omit() %>%
        filter(NName == virName) %>%
        group_by(Impact) %>%
        summarise(count = n())

    count.high <- filter(temp.df, Impact=="High") %>% select(count)
    count.med <- filter(temp.df, Impact=="Medium") %>% select(count)
    count.low <- filter(temp.df, Impact=="Low") %>% select(count)

    tot.count <- sum(tot.high$count*3, tot.med$count*2, tot.low$count*1, na.rm=TRUE)

    norm.high <- count.high/tot.count
    norm.med <- count.med/tot.count
    norm.low <- count.low/tot.count

    t <- rbind("Low"=norm.low, "Medium"=norm.med, "High"=norm.high)
    t$Impact <- rownames(t)

    temp.df <- left_join(temp.df, t, by="Impact")
    names(temp.df) <- c("Impact", "Count", "Norm.Count")
    return(sum(temp.df$Norm.Count, na.rm=TRUE))
}

# Q8  : What is the most infective virus amongst others?

# `norm.infect` function counts the different
# levels of infections differently (`High`: 3, `Medium`: 2,
# `Low`: 1) and normalizes the according values.
# The function takes two arguments: The first is the dataframe to work on,
# the second is the virus name to investigate. The function returns sum
# of normalized count value for a given virus.
norm.infect <- function(df, virName) {
    tot.df <- df %>%
        na.omit() %>%
        group_by(Infections) %>%
        summarise(count = n())

    tot.high <- filter(tot.df, Infections=="High") %>% select(count)
    tot.med <- filter(tot.df, Infections=="Medium") %>% select(count)
    tot.low <- filter(tot.df, Infections=="Low") %>% select(count)

    temp.df <- df %>%
        na.omit() %>%
        filter(NName == virName) %>%
        group_by(Infections) %>%
        summarise(count = n())

    count.high <- filter(temp.df, Infections=="High") %>% select(count)
    count.med <- filter(temp.df, Infections=="Medium") %>% select(count)
    count.low <- filter(temp.df, Infections=="Low") %>% select(count)

    tot.count <- sum(tot.high$count*3, tot.med$count*2, tot.low$count*1, na.rm=TRUE)

    norm.high <- count.high/tot.count
    norm.med <- count.med/tot.count
    norm.low <- count.low/tot.count

    t <- rbind("Low"=norm.low, "Medium"=norm.med, "High"=norm.high)
    t$Infections <- rownames(t)

    temp.df <- left_join(temp.df, t, by="Infections")
    names(temp.df) <- c("Infections", "Count", "Norm.Count")
    return(sum(temp.df$Norm.Count, na.rm=TRUE))
}
# Q9  : Which virus has the longest lifetime?

# `cre.fun` function
cre.fun <- function(df, virName) {
    total.num.days <- as.integer(as.Date(now()) - as.Date(min(df$VDFDate, na.rm=TRUE)))
    check.df <- filter(df, NName == virName) %>% select(VDFDate)
    date.dif <- as.integer(as.Date(now()) - as.Date(min(check.df$VDFDate, na.rm=TRUE)))
    return(date.dif/total.num.days)
}

# Q10 : How long has these viruses are around/ and known that they
#       are around (i.e. they are documented)

# `life.fun` function calculates the known-life-time of a virus and returns
# normalized lifetime value. This function takes the difference between
# now() and main dataframe's `VDFDate` as the total time frame (tot.num.days).
# The virus' $DateDiscovered is the documentation date.
# The function takes two arguments: The first is the dataframe to work on,
# the second is the virus name to investigate.
life.fun <- function(df, virName) {
    total.num.days <- as.integer(as.Date(now()) - as.Date(min(df$VDFDate, na.rm=TRUE)))
    check.df <- filter(df, NName == virName) %>% select(DateDiscovered)
    date.dif <- as.integer(as.Date(now()) - as.Date(min(check.df$DateDiscovered)))
    return(date.dif/total.num.days)
}

# Q11 : How many of those viruses are relatively inactive?

# `act.last.fun` function calculates the normalized last-seen "time interval"
# of a virus. This function takes the difference between now() and main dataframe's
# `VDFDate` as the total time frame (tot.num.days). The virus' max($DateDiscovered)
# is the last seen date.
# The function takes two arguments: The first is the dataframe to work on,
# the second is the virus name to investigate.
act.last.fun <- function(df, virName) {
    total.num.days <- as.integer(as.Date(now()) - as.Date(min(df$VDFDate, na.rm=TRUE)))
    check.df <- filter(df, NName == virName) %>% select(DateDiscovered)
    date.dif <- as.integer(as.Date(now()) - as.Date(max(check.df$DateDiscovered)))
    return(date.dif/total.num.days)
}

# Q12 : Which viruses update the most, as well as the least?

# `dif.fun` function calculates the normalized average number of days between
# updates of a given virus. This function creates pairs of unique values of `NExt1`
# column of a given virus and calculates average time interval between their last seen
# date. After that, calculates the mean of the result. This function takes the
# difference between now() and main dataframe's `VDFDate` as the total time frame
# (tot.num.days) and calculates normalized average number of days between updates
# according to this.
# The function takes two arguments: The first is the dataframe to work on,
# the second is the virus name to investigate.
dif.fun <- function(df, virName) {
    total.num.days <- as.integer(as.Date(now()) - as.Date(min(df$VDFDate, na.rm=TRUE)))
    check.df <- filter(df, NName == virName) %>% select(NExt1, DateDiscovered)
    m <- unique(check.df$NExt1)
    check.list <- combn(m, 2)
    date.dif <- c()
    for (i in 1:length(check.list)) {
        date.dif[i] = abs(max(as.Date(check.df$DateDiscovered[check.df$NExt1 == check.list[i]])) -
                         max(as.Date(check.df$DateDiscovered[check.df$NExt1 == check.list[i+1]])))
    }
    return(mean(date.dif, na.rm=TRUE)/total.num.days)
}

# `plt_heatmap` function creates a heatmap answering the questions mentioned
# in the beginning of this script. The function takes two arguments: The first is
# the dataframe to work on, the second is the virus name to investigate. This function
# returns the heatmap plot.
plt_heatmap <- function(df, virNameList) {
    norm.impact.vec <- c()
    norm.inf.vec <- c()
    avg_days_created <- c()
    avg_days_since_added <- c()
    avg_days_since_last_act <- c()
    avg_days_between_updates <- c()
    for (i in 1:length(virNameList)) {
        norm.impact.vec[i] <- norm.impact(df, virNameList[i])
        norm.inf.vec[i] <- norm.infect(df, virNameList[i])
        avg_days_created[i] <- cre.fun(df, virNameList[i])
        avg_days_since_added[i] <- life.fun(df, virNameList[i])
        avg_days_since_last_act[i] <- act.last.fun(df, virNameList[i])
        avg_days_between_updates[i] <- dif.fun(df, virNameList[i])
    }

    ## Heatmap
    sd <- data.frame(impact=norm.impact.vec,
                     infections=norm.inf.vec,
                     created=avg_days_created,
                     added=avg_days_since_added,
                     last_act=avg_days_since_last_act,
                     between_upd=avg_days_between_updates,
                     row.names = virNameList)
    sd.mat <- as.matrix(sd)

    par(oma=c(2,2,2,2))
    sd_heatmap <- heatmap(sd.mat, Rowv=NA, Colv=NA, col = cm.colors(256),
                         scale="column", margins=c(6,10), cexRow=1, cexCol=1)
}
# Explore the properties of most frequent 10 viruses with heatmap.
plt_heatmap(df, virCount$NName[1:10])
